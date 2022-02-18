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

class CorsServiceTest extends TestCase
{
    /**
     * @test
     */
    public function it_can_have_options()
    {
        $service = new CorsService([
            'allowedOrigins' => ['*']
        ]);

        $this->assertInstanceOf(CorsService::class, $service);
    }

    /**
     * @test
     */
    public function it_can_have_no_options()
    {
        $service = new CorsService();
        $this->assertInstanceOf(CorsService::class, $service);
    }

    /**
     * @test
     */
    public function it_can_have_empty_options()
    {
        $service = new CorsService([]);
        $this->assertInstanceOf(CorsService::class, $service);
    }

    /**
     * @test
     */
    public function it_throws_exception_on_invalid_exposed_headers()
    {
        $this->expectException(InvalidOptionException::class);

        $service = new CorsService(['exposedHeaders' => true]);
    }

    /**
     * @test
     */
    public function it_throws_exception_on_invalid_origins_array()
    {
        $this->expectException(InvalidOptionException::class);

        $service = new CorsService(['allowedOrigins' => 'string']);
    }

    /**
     * @test
     */
    public function it_normalizes_wildcard_options()
    {
        $origins = ['*'];

        $service = new CorsService(['allowedOrigins' => $origins]);
        $this->assertInstanceOf(CorsService::class, $service);

        $this->assertEquals(true, $this->getOptionsFromService($service)['allowedOrigins']);
    }

    /**
     * @test
     */
    public function it_converts_origin_patterns()
    {
        $service = new CorsService(['allowedOrigins' => ['*.mydomain.com']]);
        $this->assertInstanceOf(CorsService::class, $service);

        $patterns = $this->getOptionsFromService($service)['allowedOriginsPatterns'];
        $this->assertEquals(['#^.*\.mydomain\.com\z#u'], $patterns);
    }

    /**
     * @test
     */
    public function it_normalizes_underscore_options()
    {
        $origins = ['localhost'];

        $service = new CorsService(['allowed_origins' => $origins]);
        $this->assertInstanceOf(CorsService::class, $service);

        $this->assertEquals($origins, $this->getOptionsFromService($service)['allowedOrigins']);
    }

    private function getOptionsFromService(CorsService $service)
    {
        $reflected = new \ReflectionClass($service);

        $property = $reflected->getProperty('options');
        $property->setAccessible(true);

        return $property->getValue($service);
    }
}
