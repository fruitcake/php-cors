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
}
