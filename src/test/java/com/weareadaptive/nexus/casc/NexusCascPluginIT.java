package com.weareadaptive.nexus.casc;

import org.apache.http.*;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.ServiceUnavailableRetryStrategy;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.*;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.protocol.HttpContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class NexusCascPluginIT {
    public static int MAX_RETRIES = 10;
    public static long RETRY_INTERVAL_MS = 10000;

    private Logger logger = LoggerFactory.getLogger(NexusCascPlugin.class);
    private URL base_url;
    private HttpHost httpHost;
    private CredentialsProvider credentialsProvider;
    private RequestConfig requestConfig;
    private ServiceUnavailableRetryStrategy retryStrategy;
    private HttpRequestRetryHandler retryHandler;
    private CloseableHttpClient client;

    @BeforeAll
    void testSetup() throws MalformedURLException {
        String url = System.getenv("NEXUS_URL");
        logger.info("URL: {}", url);;
        base_url = new URL(System.getenv("NEXUS_URL"));
        httpHost = HttpHost.create(base_url.toString());

        credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(
            new AuthScope( httpHost ),
            new UsernamePasswordCredentials("johndoe","admin123")
        );

        requestConfig = RequestConfig.copy(RequestConfig.DEFAULT)
                .setSocketTimeout(5000)
                .setConnectTimeout(5000)
                .setConnectionRequestTimeout(5000)
                .build();

        // Poll up to 60s until Gateway health check succeeds (*2 = 120s total)
        retryStrategy = new ServiceUnavailableRetryStrategy()
        {
            @Override
            public boolean retryRequest(
                    final HttpResponse response,
                    final int executionCount,
                    final HttpContext context)
            {
                int statusCode = response.getStatusLine().getStatusCode();
                // Retry on non-success codes
                return (executionCount <= MAX_RETRIES) && (HttpStatus.SC_MULTIPLE_CHOICES <= statusCode); // 300+
            }

            @Override
            public long getRetryInterval()
            {
                return RETRY_INTERVAL_MS;
            }
        };

        retryHandler = new HttpRequestRetryHandler() {
            @Override
            public boolean retryRequest(IOException e, int n, HttpContext context) {
                if (n >= MAX_RETRIES) {
                    // Do not retry if over max retry count
                    return false;
                }
                if (e instanceof ConnectException) {
                    return true;
                }
                if (e instanceof InterruptedIOException) {
                    // Timeout
                    return true;
                }
                if (e instanceof ConnectTimeoutException) {
                    // Connection refused
                    return true;
                }
                HttpClientContext clientContext = HttpClientContext.adapt(context);
                HttpRequest request = clientContext.getRequest();
                boolean idempotent = !(request instanceof HttpEntityEnclosingRequest);
                if (idempotent) {
                    // Retry if the request is considered idempotent
                    try
                    {
                        Thread.sleep(RETRY_INTERVAL_MS);
                    }
                    catch (final InterruptedException ex)
                    {
                    }
                    return true;
                }
                return false;
            }
        };

        client = HttpClients.custom()
            .setDefaultCredentialsProvider(credentialsProvider)
            .setDefaultRequestConfig(requestConfig)
            .setServiceUnavailableRetryStrategy(retryStrategy)
            .setRetryHandler(retryHandler)
            .build();
    }

    @AfterAll
    void afterAll() {
        if (client != null) {
            try {
                client.close();
            } catch (IOException e) {
            } finally {
                client = null;
            }
        }
    }

    @Test
    void testAdminUser() throws URISyntaxException, IOException {
        // Setup pre-emptive authentication for this request
        BasicAuthCache authCache = new BasicAuthCache();
        BasicScheme basicAuth = new BasicScheme();
        authCache.put(httpHost, basicAuth);
        HttpClientContext localContext = HttpClientContext.create();
        localContext.setAuthCache(authCache);
        HttpGet httpGet = new HttpGet(base_url.toString() + "/service/metrics/prometheus");

        try (CloseableHttpResponse response = client.execute(httpHost, httpGet, localContext)) {
            StatusLine status = response.getStatusLine();
            assertEquals(200, status.getStatusCode());
        }
    }
}
