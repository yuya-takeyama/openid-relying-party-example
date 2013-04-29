<?php
require_once __DIR__.'/../vendor/autoload.php';
set_include_path(
    __DIR__ . '/../src' .
    PATH_SEPARATOR .
    get_include_path()
);
ini_set('display_errors', 'On');

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

$app = new Silex\Application;

$app['debug'] = true;
$app['root']  = __DIR__ . '/..';

$app['server.scheme'] = isset($_SERVER['HTTPS']) ? 'https' : 'http';
$app['server.host']   = $_SERVER['SERVER_NAME'];
$app['server.port']   = $_SERVER['SERVER_PORT'];
$app['server.host_plus_port'] = $app['server.host'] .
    ($app['server.scheme'] === 'http' ?
        ((int)$app['server.port'] !== 80 ? ":{$app['server.port']}" : '') :
        ((int)$app['server.port'] !== 443 ? ":{$app['server.port']}" : ''));
$app['server.root'] = "{$app['server.scheme']}://{$app['server.host_plus_port']}";

$app->register(new \Yuyat\OpenIdRelyingPartyExample\OpenIdServiceProvider);
$app->register(new \Silex\Provider\SessionServiceProvider);
$app->register(new \Silex\Provider\TwigServiceProvider, array(
    'twig.path' => __DIR__ . '/../views',
));

$app->before(function () use ($app) {
    $app['session']->start();

    $app['twig']->addGlobal('layout', $app['twig']->loadTemplate('layout.twig'));
    $app['twig']->addGlobal('session', $app['session']);

    require_once 'Auth/OpenID/SReg.php';
    require_once 'Auth/OpenID/PAPE.php';

    $app['twig']->addGlobal('pape_policy_uris', array(
        PAPE_AUTH_MULTI_FACTOR_PHYSICAL,
        PAPE_AUTH_MULTI_FACTOR,
        PAPE_AUTH_PHISHING_RESISTANT,
    ));

    $app['flash'] = $app->share(function ($app) use ($app) {
        return $app['session']->getFlashBag();
    });
});

$app->post('/auth/openid/try', function (Request $req) use ($app) {
    $openId = $req->get('openid_identifier');

    if (is_null($openId)) {
        $app['flash']->set('warning', 'Expected an OpenID URL.');

        return $app->redirect('/');
    }

    $consumer = $app['openid.consumer'];
    $authReq  = $consumer->begin($openId);

    if (!$authReq) {
        $app['flash']->set('error', 'Authentication Error; not a valid OpenID.');

        return $app->redirect('/');
    }

    $sregReq = \Auth_OpenID_SRegRequest::build(
        array('nickname'),
        array('fullname', 'email')
    );

    if ($sregReq) {
        $authReq->addExtension($sregReq);
    }

    $trustRoot = $app['server.root'];
    $returnTo  = "{$app['server.root']}/auth/openid/finish";

    if ($authReq->shouldSendRedirect()) {
        $redirectUrl = $authReq->redirectURL($trustRoot, $returnTo);

        if (Auth_OpenID::isFailure($redirectUrl)) {
            $app['flash']->set('error', 'Could not redirect to server: ' . $redirectUrl->message);

            return $app->redirect('/');
        } else {
            return $app->redirect($redirectUrl);
        }
    } else {
        $formHtml = $authReq->htmlMarkup(
            $trustRoot,
            $returnTo,
            false,
            array('id' => 'openid_message')
        );

        if (Auth_OpenID::isFailure($formHtml)) {
            $app['flash']->set('error', 'Could not redirect to server: ' . $formHtml->message);

            return $app->redirect('/');
        } else {
            return $formHtml;
        }
    }
});

$app->get('/auth/openid/finish', function (Request $req) use ($app) {
    $consumer = $app['openid.consumer'];
    $returnTo = "{$app['server.root']}/auth/openid/finish";
    $authRes  = $consumer->complete($returnTo);

    if ($authRes->status === Auth_OpenID_CANCEL) {
        $app['flash']->set('alert', 'Verification cancelled.');

        return $app->redirect('/');
    } else if ($authRes->status === Auth_OpenID_FAILURE) {
        $app['flash']->set('error', 'OpenID authentication failed: ' . $authRes->message);
    } else if ($authRes->status === Auth_OpenID_SUCCESS) {
        $openId = $authRes->getDisplayIdentifier();

        $message = sprintf('You have successfully verified %s as your identity.', $openId);

        if ($authRes->endpoint->canonicalID) {
            $message .= sprintf(' (XRI CanonicalID: %s)', $authRes->endpoint->canonicalID);
        }

        $sregRes = Auth_OPenID_SRegResponse::fromSuccessResponse($authRes);

        $sreg = $sregRes->contents();

        foreach ($sreg as $key => $value) {
            $message .= sprintf(" Your '%s' is '%s'.", $key, $value);
        }

        $app['flash']->set('success', $message);

        return $app->redirect('/');
    }
});

$app->get('/', function () use ($app) {
    return $app['twig']->render('index.twig');
});

$app->run();
