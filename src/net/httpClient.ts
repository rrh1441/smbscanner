/**
 * HTTP Client - Simple fetch wrapper with timeout and retry support
 */

export interface HttpClientOptions {
  timeout?: number;
  retries?: number;
  headers?: Record<string, string>;
  followRedirects?: boolean;
  maxContentLength?: number;
  validateStatus?: (status: number) => boolean;
  maxRedirects?: number;
}

export interface HttpResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  data: string; // Alias for body
  url: string;
}

const DEFAULT_TIMEOUT = 10000;
const DEFAULT_RETRIES = 2;

export async function httpGet(
  url: string,
  options: HttpClientOptions = {}
): Promise<HttpResponse> {
  const { timeout = DEFAULT_TIMEOUT, retries = DEFAULT_RETRIES, headers = {} } = options;

  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': 'SimplCyber-Scanner/1.0',
          ...headers
        },
        signal: controller.signal,
        redirect: options.followRedirects === false ? 'manual' : 'follow'
      });

      clearTimeout(timeoutId);

      const body = await response.text();
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      return {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        body,
        data: body,
        url: response.url
      };
    } catch (error) {
      lastError = error as Error;
      if (attempt < retries) {
        await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
      }
    }
  }

  throw lastError || new Error('HTTP request failed');
}

export async function httpHead(
  url: string,
  options: HttpClientOptions = {}
): Promise<HttpResponse> {
  const { timeout = DEFAULT_TIMEOUT, headers = {} } = options;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      method: 'HEAD',
      headers: {
        'User-Agent': 'SimplCyber-Scanner/1.0',
        ...headers
      },
      signal: controller.signal,
      redirect: options.followRedirects === false ? 'manual' : 'follow'
    });

    clearTimeout(timeoutId);

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    return {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: '',
      data: '',
      url: response.url
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

export async function httpPost(
  url: string,
  body: string | object,
  options: HttpClientOptions = {}
): Promise<HttpResponse> {
  const { timeout = DEFAULT_TIMEOUT, headers = {} } = options;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const isJson = typeof body === 'object';
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'User-Agent': 'SimplCyber-Scanner/1.0',
        ...(isJson ? { 'Content-Type': 'application/json' } : {}),
        ...headers
      },
      body: isJson ? JSON.stringify(body) : body,
      signal: controller.signal,
      redirect: options.followRedirects === false ? 'manual' : 'follow'
    });

    clearTimeout(timeoutId);

    const responseBody = await response.text();
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    return {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      body: responseBody,
      data: responseBody,
      url: response.url
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

// Aliases for compatibility with existing code
export const httpRequest = httpGet;
export const httpGetText = async (url: string, options?: HttpClientOptions): Promise<string> => {
  const response = await httpGet(url, options);
  return response.body;
};

// httpClient object for named import compatibility
export const httpClient = {
  get: httpGet,
  head: httpHead,
  post: httpPost,
  request: httpGet
};

export default { httpGet, httpHead, httpPost, httpRequest, httpGetText, httpClient };
