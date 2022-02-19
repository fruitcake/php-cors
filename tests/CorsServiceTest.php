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

namespace Fruitcake\Cors\Tests;

use Fruitcake\Cors\CorsService;
use Fruitcake\Cors\Exceptions\InvalidOptionException;
use PHPUnit\Framework\TestCase;

/**
 * @phpstan-import-type CorsNormalizedOptions from CorsService
 */
class CorsServiceTest extends TestCase
{
    /**
     * @test
     */
    public function itCanHaveOptions(): void
    {
        $options = [
            'allowedOrigins' => ['localhost'],
            'allowedOriginsPatterns' => ['/something/'],
            'allowedHeaders' => ['x-custom'],
            'allowedMethods' => ['PUT'],
            'maxAge' => 684,
            'supportsCredentials' => true,
            'exposedHeaders' => ['x-custom-2'],
        ];

        $service = new CorsService($options);

        $this->assertInstanceOf(CorsService::class, $service);

        $normalized = $this->getOptionsFromService($service);

        $this->assertEquals($options['allowedOrigins'], $normalized['allowedOrigins']);
        $this->assertEquals($options['allowedOriginsPatterns'], $normalized['allowedOriginsPatterns']);
        $this->assertEquals($options['allowedHeaders'], $normalized['allowedHeaders']);
        $this->assertEquals($options['allowedMethods'], $normalized['allowedMethods']);
        $this->assertEquals($options['maxAge'], $normalized['maxAge']);
        $this->assertEquals($options['supportsCredentials'], $normalized['supportsCredentials']);
        $this->assertEquals($options['exposedHeaders'], $normalized['exposedHeaders']);
    }

    /**
     * @test
     */
    public function itCanHaveNoOptions(): void
    {
        $service = new CorsService();
        $this->assertInstanceOf(CorsService::class, $service);
        $this->assertEquals([], $this->getOptionsFromService($service)['allowedOrigins']);
    }

    /**
     * @test
     */
    public function itCanHaveEmptyOptions(): void
    {
        $service = new CorsService([]);
        $this->assertInstanceOf(CorsService::class, $service);
        $this->assertEquals([], $this->getOptionsFromService($service)['allowedOrigins']);
    }

    /**
     * @test
     */
    public function itNormalizesFalseExposedHeaders(): void
    {
        $service = new CorsService(['exposedHeaders' => false]);
        $this->assertEquals([], $this->getOptionsFromService($service)['exposedHeaders']);
    }

    /**
     * @test
     */
    public function itAllowsNullMaxAge(): void
    {
        $service = new CorsService(['maxAge' => null]);
        $this->assertNull($this->getOptionsFromService($service)['maxAge']);
    }

    /**
     * @test
     */
    public function itAllowsZeroMaxAge(): void
    {
        $service = new CorsService(['maxAge' => 0]);
        $this->assertEquals(0, $this->getOptionsFromService($service)['maxAge']);
    }

    /**
     * @test
     */
    public function itThrowsExceptionOnInvalidExposedHeaders(): void
    {
        $this->expectException(InvalidOptionException::class);

        /** @phpstan-ignore-next-line */
        $service = new CorsService(['exposedHeaders' => true]);
    }

    /**
     * @test
     */
    public function itThrowsExceptionOnInvalidOriginsArray(): void
    {
        $this->expectException(InvalidOptionException::class);

        /** @phpstan-ignore-next-line */
        $service = new CorsService(['allowedOrigins' => 'string']);
    }

    /**
     * @test
     */
    public function itNormalizesWildcardOrigins(): void
    {
        $service = new CorsService(['allowedOrigins' => ['*']]);
        $this->assertInstanceOf(CorsService::class, $service);

        $this->assertTrue($this->getOptionsFromService($service)['allowAllOrigins']);
    }

    /**
     * @test
     */
    public function itNormalizesWildcardHeaders(): void
    {
        $service = new CorsService(['allowedHeaders' => ['*']]);
        $this->assertInstanceOf(CorsService::class, $service);

        $this->assertTrue($this->getOptionsFromService($service)['allowAllHeaders']);
    }

    /**
     * @test
     */
    public function itNormalizesWildcardMethods(): void
    {
        $service = new CorsService(['allowedMethods' => ['*']]);
        $this->assertInstanceOf(CorsService::class, $service);

        $this->assertTrue($this->getOptionsFromService($service)['allowAllMethods']);
    }

    /**
     * @test
     */
    public function itConvertsWildcardOriginPatterns(): void
    {
        $service = new CorsService(['allowedOrigins' => ['*.mydomain.com']]);
        $this->assertInstanceOf(CorsService::class, $service);

        $patterns = $this->getOptionsFromService($service)['allowedOriginsPatterns'];
        $this->assertEquals(['#^.*\.mydomain\.com\z#u'], $patterns);
    }

    /**
     * @test
     */
    public function itNormalizesUnderscoreOptions(): void
    {
        $options = [
            'allowed_origins' => ['localhost'],
            'allowed_origins_patterns' => ['/something/'],
            'allowed_headers' => ['x-custom'],
            'allowed_methods' => ['PUT'],
            'max_age' => 684,
            'supports_credentials' => true,
            'exposed_headers' => ['x-custom-2'],
        ];

        $service = new CorsService($options);
        $this->assertInstanceOf(CorsService::class, $service);

        $this->assertEquals($options['allowed_origins'], $this->getOptionsFromService($service)['allowedOrigins']);
        $this->assertEquals(
            $options['allowed_origins_patterns'],
            $this->getOptionsFromService($service)['allowedOriginsPatterns']
        );
        $this->assertEquals($options['allowed_headers'], $this->getOptionsFromService($service)['allowedHeaders']);
        $this->assertEquals($options['allowed_methods'], $this->getOptionsFromService($service)['allowedMethods']);
        $this->assertEquals($options['exposed_headers'], $this->getOptionsFromService($service)['exposedHeaders']);
        $this->assertEquals($options['max_age'], $this->getOptionsFromService($service)['maxAge']);
        $this->assertEquals(
            $options['supports_credentials'],
            $this->getOptionsFromService($service)['supportsCredentials']
        );
    }

    /**
     * @param CorsService $service
     * @return CorsNormalizedOptions
     */
    private function getOptionsFromService(CorsService $service): array
    {
        $reflected = new \ReflectionClass($service);

        $property = $reflected->getProperty('options');
        $property->setAccessible(true);

        /** @var CorsNormalizedOptions $options */
        $options = $property->getValue($service);

        return $options;
    }
}
