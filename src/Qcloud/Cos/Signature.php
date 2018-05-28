<?php

namespace Qcloud\Cos;

use Guzzle\Http\Message\RequestInterface;

class Signature
{
    private $accessKey;           // string: access key.
    private $secretKey;           // string: secret key.

    public function __construct($accessKey, $secretKey)
    {
        $this->accessKey = $accessKey;
        $this->secretKey = $secretKey;
    }

    public function __destruct()
    {
    }

    public function signRequest(RequestInterface $request)
    {
        $signTime      = (time() - 60) . ';' . (time() + 3600);
        $httpString    = $this->buildHttpString($request);
        $authorization = urldecode(http_build_query($this->signature($signTime, $httpString)));
        $request->setHeader('Authorization', $authorization);
    }

    public function createPresignedUrl(RequestInterface $request, $expires = "10 minutes")
    {
        $signTime   = (time() - 60) . ';' . strtotime($expires);
        $httpString = $this->buildHttpString($request);
        $request->getQuery()->merge($this->signature($signTime, $httpString));

        return $request->getUrl();
    }

    protected function buildHttpString(RequestInterface $request)
    {
        return strtolower($request->getMethod()) . "\n" . urldecode($request->getPath()) .
            "\n\nhost=" . $request->getHost() . "\n";
    }

    public function signature($signTime, $httpString)
    {
        $sha1edHttpString = sha1($httpString);
        $stringToSign     = "sha1\n$signTime\n$sha1edHttpString\n";
        $signKey          = hash_hmac('sha1', $signTime, $this->secretKey);
        $signature        = hash_hmac('sha1', $stringToSign, $signKey);

        return array(
            'q-sign-algorithm' => 'sha1',
            'q-ak'             => $this->accessKey,
            'q-sign-time'      => $signTime,
            'q-key-time'       => $signTime,
            'q-header-list'    => 'host',
            'q-url-param-list' => '',
            'q-signature'      => $signature,
        );
    }
}
