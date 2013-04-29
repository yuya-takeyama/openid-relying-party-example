<?php
namespace Yuyat\OpenIdRelyingPartyExample;

use Silex\Application;
use Silex\ServiceProviderInterface;

class OpenIdServiceProvider implements ServiceProviderInterface
{
    public function register(Application $app)
    {
        $app['openid.consumer'] = $app->share(function ($app) {
            return new \Auth_OpenID_Consumer($app['openid.store']);
        });

        $app['openid.store'] = $app->share(function ($app) {
            $path = $app['root'] . DIRECTORY_SEPARATOR . 'tmp' . DIRECTORY_SEPARATOR . 'openid';

            return new \Auth_OpenID_FileStore($path);
        });
    }

    public function boot(Application $app)
    {
    }
}
