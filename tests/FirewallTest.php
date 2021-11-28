<?php
//include('src\Firewall.php');

use PHPUnit\Framework\TestCase;
use ClsScripts\Firewall\Firewall;

require_once dirname(__DIR__).'/vendor/autoload.php';

class FirewallTest extends TestCase
{
    /**
     * @dataProvider providerUserAgent
     */
    public function test_userAgent($agentDeUser, $resultat)
    {
        $userAgentBlackListed = ['python-'];
        Firewall::init($userAgentBlackListed, [], [], [], []);
        $this->assertEquals(
            $resultat,
            Firewall::userAgentIsBlackListed(
                ['HTTP_USER_AGENT' => $agentDeUser],

            ),
            $agentDeUser
        );
    }

    public function providerUserAgent()
    {
        return [
            // agentUser, resultat
            ['python-', true],
            ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36", false],
            ["Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", false],
            ['"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"', false]
        ];
    }

    /**
     * @dataProvider providerUrlIsBlackListed
     */
    public function test_urlIsBlackListed($url, $resultat)
    {
        $excludeUrl = [
            '/server',
            '/.git',
            '/adminer.php',
            '/blog',
            '/joomla',
            '/wordpress',
            '/site(\/)*$'
        ];
        Firewall::init([], $excludeUrl, [], [], []);
        $this->assertEquals(
            $resultat,
            Firewall::urlIsBlackListed(
                ['REQUEST_URI' => $url]
            ),
            $url
        );
    }

    public function providerUrlIsBlackListed()
    {
        return [
            // url, resultat
            ['/server', true],
            ["/.git", true],
            ["/", false],
            ["\\", false],
            ['/route/', false],
            ['/sitemap.xml',false],
            ['/site',true],
            ['/site/',true]
        ];
    }

    /**
     * @dataProvider providerRefererIsBlackListed
     */
    public function test_refererIsBlackListed($referer, $resultat)
    {
        $refererBlackList = ['binance.com', 'anonymousfox.co'];

        Firewall::init([], [], $refererBlackList, [], []);
        $this->assertEquals(
            $resultat,
            Firewall::refererIsBlackListed(
                ['HTTP_REFERER' => $referer]
            ),
            $referer
        );
    }

    public function providerRefererIsBlackListed()
    {
        return [
            // url, resultat
            ['google.com', false],
            ["binance.com", true],
            ["anonymousfox.co", true],

        ];
    }

    /**
     * @dataProvider providerHostNameIsWhiteListed
     */
    public function test_hostNameIsWhiteListed($referer, $resultat)
    {
        $hostNameWhiteList = ['googlebot.com', 'google.com', 'search.msn.com','.qwant.com'];

        Firewall::init([], [], [], $hostNameWhiteList, []);
        $this->assertEquals(
            $resultat,
            Firewall::hostNameIsWhiteListed(
                ['REMOTE_ADDR' => $referer]
            ),
            $referer
        );
    }

    public function providerHostNameIsWhiteListed()
    {
        return [
            // url, resultat
            ['155.94.222.11', false],//s.potsm.com
            ["207.46.13.171", true],//msnbot-207-46-13-171.search.msn.com
            ["34.214.180.20", false],//ec2-34-214-180-20.us-west-2.compute.amazonaws.com
            ["66.249.66.149", true],//crawl-66-249-66-149.googlebot.com
        ];
    }
    /**
     * @dataProvider providerIpIsWhiteListed
     */
    public function test_IpIsWhiteListed($referer, $resultat)
    {
        $hostNameWhiteList = ['127.0.0.1', '1.2.3.4'];

        Firewall::init([], [], [], [], $hostNameWhiteList);
        $this->assertEquals(
            $resultat,
            Firewall::ipIsWhiteListed(
                ['REMOTE_ADDR' => $referer]
            ),
            $referer
        );
    }

    public function providerIpIsWhiteListed()
    {
        return [
            // url, resultat
            ['127.0.0.1', true],//
            ["1.2.3.4", true],
            ['6.7.8.9',false]
            ];
    }
}