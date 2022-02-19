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
    public function itCanHaveOptions()
    {
        $service = new CorsService([
            'allowedOrigins' => ['localhost']
        ]);

        $this->assertInstanceOf(CorsService::class, $service);
        $this->assertEquals(['localhost'], $this->getOptionsFromService($service)['allowedOrigins']);
    }

    /**
     * @test
     */
    public function itCanHaveNoOptions()
    {
        $service = new CorsService();
        $this->assertInstanceOf(CorsService::class, $service);
        $this->assertEquals([], $this->getOptionsFromService($service)['allowedOrigins']);
    }

    /**
     * @test
     */
    public function itCanHaveEmptyOptions()
    {
        $service = new CorsService([]);
        $this->assertInstanceOf(CorsService::class, $service);
        $this->assertEquals([], $this->getOptionsFromService($service)['allowedOrigins']);
    }

    /**
     * @test
     */
    public function itThrowsExceptionOnInvalidExposedHeaders()
    {
        $this->expectException(InvalidOptionException::class);

        $service = new CorsService(['exposedHeaders' => true]);
    }

    /**
     * @test
     */
    public function itThrowsExceptionOnInvalidOriginsArray()
    {
        $this->expectException(InvalidOptionException::class);

        $service = new CorsService(['allowedOrigins' => 'string']);
    }

    /**
     * @test
     */
    public function itNormalizesWildcardOrigins()
    {
        $origins = ['*'];

        $service = new CorsService(['allowedOrigins' => $origins]);
        $this->assertInstanceOf(CorsService::class, $service);

        $this->assertEquals(true, $this->getOptionsFromService($service)['allowedOrigins']);
    }

    /**
     * @test
     */
    public function itConvertsWildcardOriginPatterns()
    {
        $service = new CorsService(['allowedOrigins' => ['*.mydomain.com']]);
        $this->assertInstanceOf(CorsService::class, $service);

        $patterns = $this->getOptionsFromService($service)['allowedOriginsPatterns'];
        $this->assertEquals(['#^.*\.mydomain\.com\z#u'], $patterns);
    }

    /**
     * @test
     */
    public function itNormalizesUnderscoreOptions()
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
