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

/**
 * @phpstan-type CorsInputOptions array{
 *  'allowedOrigins'?: string[],
 *  'allowedOriginsPatterns'?: string[],
 *  'supportsCredentials'?: bool,
 *  'allowedHeaders'?: string[],
 *  'allowedMethods'?: string[],
 *  'exposedHeaders'?: string[]|false,
 *  'maxAge'?: int|bool|null,
 *  'allowed_origins'?: string[],
 *  'allowed_origins_patterns'?: string[],
 *  'supports_credentials'?: bool,
 *  'allowed_headers'?: string[],
 *  'allowed_methods'?: string[],
 *  'exposed_headers'?: string[]|false,
 *  'max_age'?: int|bool|null
 * }
 *
 * @phpstan-type CorsNormalizedOptions array{
 *  'allowedOrigins': string[],
 *  'allowedOriginsPatterns': string[],
 *  'supportsCredentials': bool,
 *  'allowedHeaders': string[],
 *  'allowedMethods': string[],
 *  'exposedHeaders': string[],
 *  'maxAge': int|bool|null,
 *  'allowAllOrigins': bool,
 *  'allowAllHeaders': bool,
 *  'allowAllMethods': bool,
 * }
 */
class CorsService
{
    /** @var CorsNormalizedOptions */
    private $options;

    /**
     * @param CorsInputOptions $options
     */
    public function __construct(array $options = [])
    {
        $this->options = $this->normalizeOptions($options);
    }

    /**
     * @param CorsInputOptions $options
     * @return CorsNormalizedOptions
     */
    private function normalizeOptions(array $options = []): array
    {
        $options['allowedOrigins'] = $options['allowedOrigins'] ?? $options['allowed_origins'] ?? [];
        $options['allowedOriginsPatterns'] =
            $options['allowedOriginsPatterns'] ?? $options['allowed_origins_patterns'] ?? [];
        $options['allowedMethods'] = $options['allowedMethods'] ?? $options['allowed_methods'] ?? [];
        $options['allowedHeaders'] = $options['allowedHeaders'] ?? $options['allowed_headers'] ?? [];
        $options['exposedHeaders'] = $options['exposedHeaders'] ?? $options['exposed_headers'] ?? [];
        $options['supportsCredentials'] = $options['supportsCredentials'] ?? $options['supports_credentials'] ?? false;

        if (!array_key_exists('maxAge', $options)) {
            $options['maxAge'] = array_key_exists('max_age', $options) ? $options['max_age'] : 0;
        }

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

        // Normalize case
        $options['allowedHeaders'] = array_map('strtolower', $options['allowedHeaders']);
        $options['allowedMethods'] = array_map('strtoupper', $options['allowedMethods']);

        // Normalize ['*'] to true
        $options['allowAllOrigins'] = in_array('*', $options['allowedOrigins']);
        $options['allowAllHeaders'] = in_array('*', $options['allowedHeaders']);
        $options['allowAllMethods'] = in_array('*', $options['allowedMethods']);

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
        if ($this->options['allowAllOrigins'] === true) {
            return true;
        }

        $origin = (string) $request->headers->get('Origin');

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

    private function configureAllowedOrigin(Response $response, Request $request): void
    {
        if ($this->options['allowAllOrigins'] === true && !$this->options['supportsCredentials']) {
            // Safe+cacheable, allow everything
            $response->headers->set('Access-Control-Allow-Origin', '*');
        } elseif ($this->isSingleOriginAllowed()) {
            // Single origins can be safely set
            $response->headers->set('Access-Control-Allow-Origin', array_values($this->options['allowedOrigins'])[0]);
        } else {
            // For dynamic headers, set the requested Origin header when set and allowed
            if ($this->isCorsRequest($request) && $this->isOriginAllowed($request)) {
                $response->headers->set('Access-Control-Allow-Origin', (string) $request->headers->get('Origin'));
            }

            $this->varyHeader($response, 'Origin');
        }
    }

    private function isSingleOriginAllowed(): bool
    {
        if ($this->options['allowAllOrigins'] === true || count($this->options['allowedOriginsPatterns']) > 0) {
            return false;
        }

        return count($this->options['allowedOrigins']) === 1;
    }

    private function configureAllowedMethods(Response $response, Request $request): void
    {
        if ($this->options['allowAllMethods'] === true) {
            $allowMethods = strtoupper((string) $request->headers->get('Access-Control-Request-Method'));
            $this->varyHeader($response, 'Access-Control-Request-Method');
        } else {
            $allowMethods = implode(', ', $this->options['allowedMethods']);
        }

        $response->headers->set('Access-Control-Allow-Methods', $allowMethods);
    }

    private function configureAllowedHeaders(Response $response, Request $request): void
    {
        if ($this->options['allowAllHeaders'] === true) {
            $allowHeaders = (string) $request->headers->get('Access-Control-Request-Headers');
            $this->varyHeader($response, 'Access-Control-Request-Headers');
        } else {
            $allowHeaders = implode(', ', $this->options['allowedHeaders']);
        }
        $response->headers->set('Access-Control-Allow-Headers', $allowHeaders);
    }

    private function configureAllowCredentials(Response $response, Request $request): void
    {
        if ($this->options['supportsCredentials']) {
            $response->headers->set('Access-Control-Allow-Credentials', 'true');
        }
    }

    private function configureExposedHeaders(Response $response, Request $request): void
    {
        if ($this->options['exposedHeaders']) {
            $response->headers->set('Access-Control-Expose-Headers', implode(', ', $this->options['exposedHeaders']));
        }
    }

    private function configureMaxAge(Response $response, Request $request): void
    {
        if ($this->options['maxAge'] !== null) {
            $response->headers->set('Access-Control-Max-Age', (string) $this->options['maxAge']);
        }
    }

    public function varyHeader(Response $response, string $header): Response
    {
        if (!$response->headers->has('Vary')) {
            $response->headers->set('Vary', $header);
        } elseif (!in_array($header, explode(', ', (string) $response->headers->get('Vary')))) {
            $response->headers->set('Vary', ((string) $response->headers->get('Vary')) . ', ' . $header);
        }

        return $response;
    }
}
