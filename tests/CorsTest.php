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
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class CorsTest extends TestCase
{
    /**
     * @test
     */
    public function itDoesModifyOnARequestWithoutOrigin()
    {
        $app = $this->createStackedApp();

        $response = $app->handle(new Request());

        $this->assertEquals('http://localhost', $response->headers->get('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function itDoesModifyOnARequestWithSameOrigin()
    {
        $app = $this->createStackedApp(array('allowedOrigins' => array('*')));
        $unmodifiedResponse = new Response();

        $request  = new Request();
        $request->headers->set('Host', 'foo.com');
        $request->headers->set('Origin', 'http://foo.com');
        $response = $app->handle($request);

        $this->assertEquals('*', $response->headers->get('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function itReturnsAllowOriginHeaderOnValidActualRequest()
    {
        $app      = $this->createStackedApp();
        $request  = $this->createValidActualRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Access-Control-Allow-Origin'));
        $this->assertEquals('http://localhost', $response->headers->get('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function itReturnsAllowOriginHeaderOnAllowAllOriginRequest()
    {
        $app      = $this->createStackedApp(array('allowedOrigins' => array('*')));
        $request  = new Request();
        $request->headers->set('Origin', 'http://localhost');

        $response = $app->handle($request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertTrue($response->headers->has('Access-Control-Allow-Origin'));
        $this->assertEquals('*', $response->headers->get('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function itReturnsAllowHeadersHeaderOnAllowAllHeadersRequest()
    {
        $app     = $this->createStackedApp(array('allowedHeaders' => array('*')));
        $request = $this->createValidPreflightRequest();
        $request->headers->set('Access-Control-Request-Headers', 'Foo, BAR');

        $response = $app->handle($request);

        $this->assertEquals(204, $response->getStatusCode());
        $this->assertEquals('Foo, BAR', $response->headers->get('Access-Control-Allow-Headers'));
        $this->assertEquals('Access-Control-Request-Headers, Access-Control-Request-Method', $response->headers->get('Vary'));
    }

    /**
     * @test
     */
    public function itReturnsAllowHeadersHeaderOnAllowAllHeadersRequestCredentials()
    {
        $app      = $this->createStackedApp(array('allowedHeaders' => array('*'), 'supportsCredentials' => true));
        $request = $this->createValidPreflightRequest();
        $request->headers->set('Access-Control-Request-Headers', 'Foo, BAR');

        $response = $app->handle($request);

        $this->assertEquals(204, $response->getStatusCode());
        $this->assertEquals('Foo, BAR', $response->headers->get('Access-Control-Allow-Headers'));
        $this->assertEquals('Access-Control-Request-Headers, Access-Control-Request-Method', $response->headers->get('Vary'));
    }

    /**
     * @test
     */
    public function itSetsAllowCredentialsHeaderWhenFlagIsSetOnValidActualRequest()
    {
        $app     = $this->createStackedApp(array('supportsCredentials' => true));
        $request = $this->createValidActualRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Access-Control-Allow-Credentials'));
        $this->assertEquals('true', $response->headers->get('Access-Control-Allow-Credentials'));
    }

    /**
     * @test
     */
    public function itDoesNotSetAllowCredentialsHeaderWhenFlagIsNotSetOnValidActualRequest()
    {
        $app     = $this->createStackedApp();
        $request = $this->createValidActualRequest();

        $response = $app->handle($request);

        $this->assertFalse($response->headers->has('Access-Control-Allow-Credentials'));
    }

    /**
     * @test
     */
    public function itSetsExposedHeadersWhenConfiguredOnActualRequest()
    {
        $app     = $this->createStackedApp(array('exposedHeaders' => array('x-exposed-header', 'x-another-exposed-header')));
        $request = $this->createValidActualRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Access-Control-Expose-Headers'));
        $this->assertEquals('x-exposed-header, x-another-exposed-header', $response->headers->get('Access-Control-Expose-Headers'));
    }

    /**
     * @test
     */
    public function itAddsAVaryHeaderWhenWildcardAndSupportsCredentials()
    {
        $app      = $this->createStackedApp(array(
            'allowedOrigins' => ['*'],
            'supportsCredentials' => true,
        ));
        $request  = $this->createValidActualRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Vary'));
        $this->assertEquals('Origin', $response->headers->get('Vary'));
    }

    /**
     * @test
     */
    public function itAddsMultipleVaryHeaderWhenWildcardAndSupportsCredentials()
    {
        $app = $this->createStackedApp(array(
            'allowedOrigins' => ['*'],
            'allowedMethods' => ['*'],
            'supportsCredentials' => true,
        ));
        $request  = $this->createValidPreflightRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Vary'));
        $this->assertEquals('Origin, Access-Control-Request-Method', $response->headers->get('Vary'));
    }

    /**
     * @test
     */
    public function itAddsAVaryHeaderWhenHasOriginPatterns()
    {
        $app      = $this->createStackedApp(array(
            'allowedOriginsPatterns' => array('/l(o|0)calh(o|0)st/')
        ));
        $request  = $this->createValidActualRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Vary'));
        $this->assertEquals('Origin', $response->headers->get('Vary'));
    }

    /**
     * @test
     */
    public function itDoesntAddAVaryHeaderWhenWilcardOrigins()
    {
        $app      = $this->createStackedApp(array(
            'allowedOrigins' => array('*', 'http://localhost')
        ));
        $request  = $this->createValidActualRequest();

        $response = $app->handle($request);

        $this->assertFalse($response->headers->has('Vary'));
    }

    /**
     * @test
     */
    public function itDoesntAddAVaryHeaderWhenSimpleOrigins()
    {
        $app = $this->createStackedApp(array(
            'allowedOrigins' => array('http://localhost')
        ));
        $request  = $this->createValidActualRequest();

        $response = $app->handle($request);

        $this->assertEquals('http://localhost', $response->headers->get('Access-Control-Allow-Origin'));
        $this->assertFalse($response->headers->has('Vary'));
    }

    /**
     * @test
     */
    public function itAddsAVaryHeaderWhenMultipleOrigins()
    {
        $app = $this->createStackedApp(array(
           'allowedOrigins' => array('http://localhost', 'http://example.com')
        ));
        $request  = $this->createValidActualRequest();

        $response = $app->handle($request);

        $this->assertEquals('http://localhost', $response->headers->get('Access-Control-Allow-Origin'));
        $this->assertTrue($response->headers->has('Vary'));
    }

    /**
     * @test
     * @see http://www.w3.org/TR/cors/index.html#resource-implementation
     */
    public function itAppendsAnExistingVaryHeader()
    {
        $app      = $this->createStackedApp(
            array(
                'allowedOrigins' => ['*'],
                'supportsCredentials' => true,
            ),
            array(
                'Vary' => 'Content-Type'
            )
        );
        $request  = $this->createValidActualRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Vary'));
        $this->assertEquals('Content-Type, Origin', $response->headers->get('Vary'));
    }

    /**
     * @test
     */
    public function itReturnsAccessControlHeadersOnCorsRequest()
    {
        $app      = $this->createStackedApp();
        $request  = new Request();
        $request->headers->set('Origin', 'http://localhost');

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Access-Control-Allow-Origin'));
        $this->assertEquals('http://localhost', $response->headers->get('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function itReturnsAccessControlHeadersOnCorsRequestWithPatternOrigin()
    {
        $app = $this->createStackedApp(array(
          'allowedOrigins' => array(),
          'allowedOriginsPatterns' => array('/l(o|0)calh(o|0)st/')
        ));
        $request  = $this->createValidActualRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Access-Control-Allow-Origin'));
        $this->assertEquals('http://localhost', $response->headers->get('Access-Control-Allow-Origin'));
        $this->assertTrue($response->headers->has('Vary'));
        $this->assertEquals('Origin', $response->headers->get('Vary'));
    }

    /**
     * @test
     */
    public function itAddsVaryHeadersOnPreflightNonPreflightOptions()
    {
        $app      = $this->createStackedApp();
        $request  = new Request();
        $request->setMethod('OPTIONS');

        $response = $app->handle($request);

        $this->assertEquals('Access-Control-Request-Method', $response->headers->get('Vary'));
    }

    /**
     * @test
     */
    public function itReturnsAccessControlHeadersOnValidPreflightRequest()
    {
        $app     = $this->createStackedApp();
        $request = $this->createValidPreflightRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Access-Control-Allow-Origin'));
        $this->assertEquals('http://localhost', $response->headers->get('Access-Control-Allow-Origin'));
        $this->assertEquals('Access-Control-Request-Method', $response->headers->get('Vary'));
    }

    /**
     * @test
     */
    public function itDoesNotAllowRequestWithOriginNotAllowed()
    {
        $passedOptions = array(
          'allowedOrigins' => array('http://notlocalhost'),
        );

        $service  = new CorsService($passedOptions);
        $request  = $this->createValidActualRequest();
        $response = new Response();
        $service->addActualRequestHeaders($response, $request);

        $this->assertNotEquals($request->headers->get('Origin'), $response->headers->get('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function itDoesNotModifyRequestWithPatternOriginNotAllowed()
    {
        $passedOptions = array(
            'allowedOrigins' => array(),
            'allowedOriginsPatterns' => array('/l\dcalh\dst/')
        );

        $service  = new CorsService($passedOptions);
        $request  = $this->createValidActualRequest();
        $response = new Response();
        $service->addActualRequestHeaders($response, $request);

        $this->assertNotEquals($request->headers->get('Origin'), $response->headers->get('Access-Control-Allow-Origin'));
    }

    /**
     * @test
     */
    public function itAllowMethodsOnValidPreflightRequest()
    {
        $app     = $this->createStackedApp(array('allowedMethods' => array('get', 'put')));
        $request = $this->createValidPreflightRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Access-Control-Allow-Methods'));
        // it will uppercase the methods
        $this->assertEquals('GET, PUT', $response->headers->get('Access-Control-Allow-Methods'));
    }

    /**
     * @test
     */
    public function itReturnsValidPreflightRequestWithAllowMethodsAll()
    {
        $app     = $this->createStackedApp(array('allowedMethods' => array('*')));
        $request = $this->createValidPreflightRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Access-Control-Allow-Methods'));
        // it will return the Access-Control-Request-Method pass in the request
        $this->assertEquals('GET', $response->headers->get('Access-Control-Allow-Methods'));
        $this->assertEquals('Access-Control-Request-Method', $response->headers->get('Vary'));
    }

    /**
     * @test
     */
    public function itReturnsValidPreflightRequestWithAllowMethodsAllCredentials()
    {
        $app     = $this->createStackedApp(array('allowedMethods' => array('*'), 'supportsCredentials' => true));
        $request = $this->createValidPreflightRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Access-Control-Allow-Methods'));
        // it will return the Access-Control-Request-Method pass in the request
        $this->assertEquals('GET', $response->headers->get('Access-Control-Allow-Methods'));
        // it should vary this header
        $this->assertEquals('Access-Control-Request-Method', $response->headers->get('Vary'));
    }

    /**
     * @test
     */
    public function itReturnsOkOnValidPreflightRequestWithRequestedHeadersAllowed()
    {
        $app            = $this->createStackedApp();
        $requestHeaders = 'X-Allowed-Header, x-other-allowed-header';
        $request        = $this->createValidPreflightRequest();
        $request->headers->set('Access-Control-Request-Headers', $requestHeaders);

        $response = $app->handle($request);

        $this->assertEquals(204, $response->getStatusCode());

        $this->assertTrue($response->headers->has('Access-Control-Allow-Headers'));
        // the response will have the "allowedHeaders" value passed to Cors rather than the request one
        $this->assertEquals('x-allowed-header, x-other-allowed-header', $response->headers->get('Access-Control-Allow-Headers'));
    }

    /**
     * @test
     */
    public function itSetsAllowCredentialsHeaderWhenFlagIsSetOnValidPreflightRequest()
    {
        $app     = $this->createStackedApp(array('supportsCredentials' => true));
        $request = $this->createValidPreflightRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Access-Control-Allow-Credentials'));
        $this->assertEquals('true', $response->headers->get('Access-Control-Allow-Credentials'));
    }

    /**
     * @test
     */
    public function itDoesNotSetAllowCredentialsHeaderWhenFlagIsNotSetOnValidPreflightRequest()
    {
        $app     = $this->createStackedApp();
        $request = $this->createValidPreflightRequest();

        $response = $app->handle($request);

        $this->assertFalse($response->headers->has('Access-Control-Allow-Credentials'));
    }

    /**
     * @test
     */
    public function itSetsMaxAgeWhenSet()
    {
        $app     = $this->createStackedApp(array('maxAge' => 42));
        $request = $this->createValidPreflightRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Access-Control-Max-Age'));
        $this->assertEquals(42, $response->headers->get('Access-Control-Max-Age'));
    }

    /**
     * @test
     */
    public function itSetsMaxAgeWhenZero()
    {
        $app     = $this->createStackedApp(array('maxAge' => 0));
        $request = $this->createValidPreflightRequest();

        $response = $app->handle($request);

        $this->assertTrue($response->headers->has('Access-Control-Max-Age'));
        $this->assertEquals(0, $response->headers->get('Access-Control-Max-Age'));
    }

    /**
     * @test
     */
    public function itDoesntSetMaxAgeWhenFalse()
    {
        $app     = $this->createStackedApp(array('maxAge' => null));
        $request = $this->createValidPreflightRequest();

        $response = $app->handle($request);

        $this->assertFalse($response->headers->has('Access-Control-Max-Age'));
    }

    /**
     * @test
     */
    public function itSkipsEmptyAccessControlRequestHeader()
    {
        $app     = $this->createStackedApp();
        $request = $this->createValidPreflightRequest();
        $request->headers->set('Access-Control-Request-Headers', '');

        $response = $app->handle($request);
        $this->assertEquals(204, $response->getStatusCode());
    }

    /**
     * @test
     */
    public function itDoesntSetAccessControlAllowOriginWithoutOrigin()
    {
        $app     = $this->createStackedApp([
            'allowedOrigins'      => ['*'],
            'supportsCredentials' => true,
        ]);

        $response = $app->handle(new Request());

        $this->assertFalse($response->headers->has('Access-Control-Allow-Origin'));
    }

    private function createValidActualRequest()
    {
        $request  = new Request();
        $request->headers->set('Origin', 'http://localhost');

        return $request;
    }

    private function createValidPreflightRequest()
    {
        $request  = new Request();
        $request->headers->set('Origin', 'http://localhost');
        $request->headers->set('Access-Control-Request-Method', 'get');
        $request->setMethod('OPTIONS');

        return $request;
    }

    private function createStackedApp(array $options = array(), array $responseHeaders = array())
    {
        $passedOptions = array_merge(
            array(
                'allowedHeaders'      => array('x-allowed-header', 'x-other-allowed-header'),
                'allowedMethods'      => array('delete', 'get', 'post', 'put'),
                'allowedOrigins'      => array('http://localhost'),
                'exposedHeaders'      => false,
                'maxAge'              => false,
                'supportsCredentials' => false,
            ),
            $options
        );

        return new MockApp($responseHeaders, $passedOptions);
    }
}
