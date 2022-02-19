<?php

/*
 * This file is part of fruitcake/php-cors and was originally part of asm89/stack-cors
 *
 * (c) Alexander <iam.asm89@gmail.com>
 * (c) Barryvdh <barryvdh@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Fruitcake\Cors;

use Fruitcake\Cors\Exceptions\InvalidOptionException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class CorsService
{
    private $options;

    public function __construct(array $options = [])
    {
        $this->options = $this->normalizeOptions($options);
    }

    private function normalizeOptions(array $options = []): array
    {
        $aliases = [
            'supports_credentials' => 'supportsCredentials',
            'allowed_origins' => 'allowedOrigins',
            'allowed_origins_patterns' => 'allowedOriginsPatterns',
            'allowed_headers' => 'allowedHeaders',
            'allowed_methods' => 'allowedMethods',
            'exposed_headers' => 'exposedHeaders',
            'max_age'  => 'maxAge',
        ];

        // Normalize underscores
        foreach ($aliases as $alias => $option) {
            if (isset($options[$alias])) {
                $options[$option] = $options[$alias];
                unset($options[$alias]);
            }
        }

        $options += [
            'allowedOrigins' => [],
            'allowedOriginsPatterns' => [],
            'supportsCredentials' => false,
            'allowedHeaders' => [],
            'exposedHeaders' => [],
            'allowedMethods' => [],
            'maxAge' => 0,
        ];

        if ($options['exposedHeaders'] === false) {
            $options['exposedHeaders'] = [];
        }

        $arrayHeaders = [
            'allowedOrigins',
            'allowedOriginsPatterns',
            'allowedHeaders',
            'allowedMethods',
            'exposedHeaders',
        ];
        foreach ($arrayHeaders as $key) {
            if (!is_array($options[$key])) {
                throw new InvalidOptionException("CORS option `{$key}` should be an array");
            }
        }

        // Transform wildcard pattern
        foreach ($options['allowedOrigins'] as $origin) {
            if (strpos($origin, '*') !== false) {
                $options['allowedOriginsPatterns'][] = $this->convertWildcardToPattern($origin);
            }
        }

        // normalize array('*') to true
        if (in_array('*', $options['allowedOrigins'])) {
            $options['allowedOrigins'] = true;
        }
        if (in_array('*', $options['allowedHeaders'])) {
            $options['allowedHeaders'] = true;
        } else {
            $options['allowedHeaders'] = array_map('strtolower', $options['allowedHeaders']);
        }

        if (in_array('*', $options['allowedMethods'])) {
            $options['allowedMethods'] = true;
        } else {
            $options['allowedMethods'] = array_map('strtoupper', $options['allowedMethods']);
        }

        return $options;
    }

    /**
     * Create a pattern for a wildcard, based on Str::is() from Laravel
     *
     * @see https://github.com/laravel/framework/blob/5.5/src/Illuminate/Support/Str.php
     * @param string $pattern
     * @return string
     */
    private function convertWildcardToPattern($pattern)
    {
        $pattern = preg_quote($pattern, '#');

        // Asterisks are translated into zero-or-more regular expression wildcards
        // to make it convenient to check if the strings starts with the given
        // pattern such as "*.example.com", making any string check convenient.
        $pattern = str_replace('\*', '.*', $pattern);

        return '#^' . $pattern . '\z#u';
    }

    public function isCorsRequest(Request $request): bool
    {
        return $request->headers->has('Origin');
    }

    public function isPreflightRequest(Request $request): bool
    {
        return $request->getMethod() === 'OPTIONS' && $request->headers->has('Access-Control-Request-Method');
    }

    public function handlePreflightRequest(Request $request): Response
    {
        $response = new Response();

        $response->setStatusCode(204);

        return $this->addPreflightRequestHeaders($response, $request);
    }

    public function addPreflightRequestHeaders(Response $response, Request $request): Response
    {
        $this->configureAllowedOrigin($response, $request);

        if ($response->headers->has('Access-Control-Allow-Origin')) {
            $this->configureAllowCredentials($response, $request);

            $this->configureAllowedMethods($response, $request);

            $this->configureAllowedHeaders($response, $request);

            $this->configureMaxAge($response, $request);
        }

        return $response;
    }

    public function isOriginAllowed(Request $request): bool
    {
        if ($this->options['allowedOrigins'] === true) {
            return true;
        }

        if (!$request->headers->has('Origin')) {
            return false;
        }

        $origin = $request->headers->get('Origin');

        if (in_array($origin, $this->options['allowedOrigins'])) {
            return true;
        }

        foreach ($this->options['allowedOriginsPatterns'] as $pattern) {
            if (preg_match($pattern, $origin)) {
                return true;
            }
        }

        return false;
    }

    public function addActualRequestHeaders(Response $response, Request $request): Response
    {
        $this->configureAllowedOrigin($response, $request);

        if ($response->headers->has('Access-Control-Allow-Origin')) {
            $this->configureAllowCredentials($response, $request);

            $this->configureExposedHeaders($response, $request);
        }

        return $response;
    }

    private function configureAllowedOrigin(Response $response, Request $request)
    {
        if ($this->options['allowedOrigins'] === true && !$this->options['supportsCredentials']) {
            // Safe+cacheable, allow everything
            $response->headers->set('Access-Control-Allow-Origin', '*');
        } elseif ($this->isSingleOriginAllowed()) {
            // Single origins can be safely set
            $response->headers->set('Access-Control-Allow-Origin', array_values($this->options['allowedOrigins'])[0]);
        } else {
            // For dynamic headers, set the requested Origin header when set and allowed
            if ($this->isCorsRequest($request) && $this->isOriginAllowed($request)) {
                $response->headers->set('Access-Control-Allow-Origin', $request->headers->get('Origin'));
            }

            $this->varyHeader($response, 'Origin');
        }
    }

    private function isSingleOriginAllowed(): bool
    {
        if ($this->options['allowedOrigins'] === true || !empty($this->options['allowedOriginsPatterns'])) {
            return false;
        }

        return count($this->options['allowedOrigins']) === 1;
    }

    private function configureAllowedMethods(Response $response, Request $request)
    {
        if ($this->options['allowedMethods'] === true) {
            $allowMethods = strtoupper($request->headers->get('Access-Control-Request-Method'));
            $this->varyHeader($response, 'Access-Control-Request-Method');
        } else {
            $allowMethods = implode(', ', $this->options['allowedMethods']);
        }

        $response->headers->set('Access-Control-Allow-Methods', $allowMethods);
    }

    private function configureAllowedHeaders(Response $response, Request $request)
    {
        if ($this->options['allowedHeaders'] === true) {
            $allowHeaders = $request->headers->get('Access-Control-Request-Headers');
            $this->varyHeader($response, 'Access-Control-Request-Headers');
        } else {
            $allowHeaders = implode(', ', $this->options['allowedHeaders']);
        }
        $response->headers->set('Access-Control-Allow-Headers', $allowHeaders);
    }

    private function configureAllowCredentials(Response $response, Request $request)
    {
        if ($this->options['supportsCredentials']) {
            $response->headers->set('Access-Control-Allow-Credentials', 'true');
        }
    }

    private function configureExposedHeaders(Response $response, Request $request)
    {
        if ($this->options['exposedHeaders']) {
            $response->headers->set('Access-Control-Expose-Headers', implode(', ', $this->options['exposedHeaders']));
        }
    }

    private function configureMaxAge(Response $response, Request $request)
    {
        if ($this->options['maxAge'] !== null) {
            $response->headers->set('Access-Control-Max-Age', (int) $this->options['maxAge']);
        }
    }

    public function varyHeader(Response $response, $header): Response
    {
        if (!$response->headers->has('Vary')) {
            $response->headers->set('Vary', $header);
        } elseif (!in_array($header, explode(', ', $response->headers->get('Vary')))) {
            $response->headers->set('Vary', $response->headers->get('Vary') . ', ' . $header);
        }

        return $response;
    }
}
