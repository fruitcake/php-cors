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
    public function itCanSetOptions(): void
    {
        $service = new CorsService();
        $normalized = $this->getOptionsFromService($service);
        $this->assertEquals([], $normalized['allowedOrigins']);

        $this->assertInstanceOf(CorsService::class, $service);

        $options = [
            'allowedOrigins' => ['localhost'],
            'allowedOriginsPatterns' => ['/something/'],
            'allowedHeaders' => ['x-custom'],
            'allowedMethods' => ['PUT'],
            'maxAge' => 684,
            'supportsCredentials' => true,
            'exposedHeaders' => ['x-custom-2'],
        ];

        $service->setOptions($options);

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
    public function itCanOverwriteSetOptions(): void
    {
        $service = new CorsService(['allowedOrigins' => ['example.com']]);
        $normalized = $this->getOptionsFromService($service);

        $this->assertEquals(['example.com'], $normalized['allowedOrigins']);

        $this->assertInstanceOf(CorsService::class, $service);

        $options = [
            'allowedOrigins' => ['localhost'],
            'allowedOriginsPatterns' => ['/something/'],
            'allowedHeaders' => ['x-custom'],
            'allowedMethods' => ['PUT'],
            'maxAge' => 684,
            'supportsCredentials' => true,
            'exposedHeaders' => ['x-custom-2'],
        ];

        $service->setOptions($options);

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

        $normalized = $this->getOptionsFromService($service);

        $this->assertEquals([], $normalized['allowedOrigins']);
        $this->assertEquals([], $normalized['allowedOriginsPatterns']);
        $this->assertEquals([], $normalized['allowedHeaders']);
        $this->assertEquals([], $normalized['allowedMethods']);
        $this->assertEquals([], $normalized['exposedHeaders']);
        $this->assertEquals(0, $normalized['maxAge']);
        $this->assertEquals(false, $normalized['supportsCredentials']);
    }

    /**
     * @test
     */
    public function itCanHaveEmptyOptions(): void
    {
        $service = new CorsService([]);
        $this->assertInstanceOf(CorsService::class, $service);

        $normalized = $this->getOptionsFromService($service);

        $this->assertEquals([], $normalized['allowedOrigins']);
        $this->assertEquals([], $normalized['allowedOriginsPatterns']);
        $this->assertEquals([], $normalized['allowedHeaders']);
        $this->assertEquals([], $normalized['allowedMethods']);
        $this->assertEquals([], $normalized['exposedHeaders']);
        $this->assertEquals(0, $normalized['maxAge']);
        $this->assertEquals(false, $normalized['supportsCredentials']);
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
        $this->expectException(\TypeError::class);

        /** @phpstan-ignore-next-line */
        $service = new CorsService(['exposedHeaders' => true]);
    }

    /**
     * @test
     */
    public function itThrowsExceptionOnInvalidOriginsArray(): void
    {
        $this->expectException(\TypeError::class);

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

        $properties = $reflected->getProperties(\ReflectionProperty::IS_PRIVATE);

        $options = [];
        foreach ($properties as $property) {
            $property->setAccessible(true);
            $options[$property->getName()] = $property->getValue($service);
        }

        /** @var CorsNormalizedOptions $options */
        return $options;
    }
}
