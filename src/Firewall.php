<?php


/*
Copyright (c)  christophe spitéri
L'autorisation est par la présente accordée, gratuitement, à toute personne obtenant une copie
de ce logiciel et des fichiers de documentation associés (le «Logiciel»), pour traiter
dans le Logiciel sans restriction, y compris sans limitation les droits
pour utiliser, copier, modifier, fusionner, publier, distribuer, sous-licencier et / ou vendre
copies du Logiciel, et pour permettre aux personnes à qui le Logiciel est
fourni à cet effet, sous réserve des conditions suivantes:
L'avis de droit d'auteur ci-dessus et cet avis d'autorisation doivent être inclus dans tous
copies ou parties substantielles du logiciel.
LE LOGICIEL EST FOURNI "EN L'ÉTAT", SANS GARANTIE D'AUCUNE SORTE, EXPRESSE OU
IMPLICITE, Y COMPRIS MAIS SANS S'Y LIMITER LES GARANTIES DE QUALITÉ MARCHANDE,
ADAPTATION À UN USAGE PARTICULIER ET NON-CONTREFAÇON. EN AUCUN CAS LE
LES AUTEURS OU LES TITULAIRES DE COPYRIGHT SONT RESPONSABLES DE TOUTE RÉCLAMATION, DOMMAGES OU AUTRES
RESPONSABILITÉ, QUE CE SOIT DANS UNE ACTION DE CONTRAT, DE TORT OU AUTRE, DÉCOULANT DE,
HORS OU EN LIEN AVEC LE LOGICIEL OU L'UTILISATION OU D'AUTRES ACTIONS DANS LE
LOGICIEL.

 */
namespace ClsScripts\Firewall;

class Firewall
{
    const FILENAME = '.htaccess';

    protected static $excludeUrl = [];

    //User_Agent
    protected static $userAgent = [];

    //Referer
    protected static $refererBlackList = [];

    // convertira l'ip en host et vérifira s'il est dans la liste
    protected static $hostNameWhiteList = [];

    // ip qu'on ne filtre pas, la sienne par exemple
    // commence par ..
    protected static $whiteListIp = [];

    protected static $test = false;

    public static function test(bool $test): void
    {
        self::$test = $test;
    }

    private static function log(string $log): void
    {
        if (self::$test) {
            echo $log;
        }
    }

    public static function init(array $userAgent, array $excludeUrl, array $refererBlackList, array $hostNameWhiteList, array $whiteListIp)
    {
        self::$userAgent         = $userAgent;
        self::$excludeUrl        = $excludeUrl;
        self::$refererBlackList  = $refererBlackList;
        self::$hostNameWhiteList = $hostNameWhiteList;
        self::$whiteListIp       = $whiteListIp;
    }

    /**
     * arrivée du firewall
     */
    public static function run(): void
    {
        if (self::ipIsWhiteListed($_SERVER)) {
            self::log('IP en liste blanche');
            return;
        }

        if (self::hostNameIsWhiteListed($_SERVER)) {
            self::log('HostName en liste Blanche');
            return;
        }

        if (self::urlIsBlackListed($_SERVER)) {
            self::addIpInBlackList();
            self::header();
            self::log('addIpInBlackList urlIsBlackListed');
            die('');
        }

        if (self::userAgentIsBlackListed($_SERVER)) {
            self::addIpInBlackList();
            self::header();
            self::log('addIpInBlackList userAgentIsBlackListed');
            die('');
        }

        if (self::refererIsBlackListed($_SERVER)) {
            self::addIpInBlackList();
            self::header();
            self::log('addIpInBlackList refererIsBlackListed');
            die('');
        }
    }

    /**
     * regarde si l'ip commence par les ip du tableau self::$whiteListIp
     * Si l'Ip est dans le tableau, retourne True, sinon False
     *
     * @return bool
     */
    public static function ipIsWhiteListed($server): bool
    {
        return self::matchPattern($server['REMOTE_ADDR']??'', self::$whiteListIp);
    }

    /**
     * vérifié si l'url commence par les ip du tableau self::$excludeUrl
     * Ip blacklistée retourne True, sinon False
     * @return bool
     */
    public static function urlIsBlackListed($server): bool
    {
        $uri = $server['REQUEST_URI'];
        if ($uri == '\\') {
            return false;
        }
        return self::matchPattern($server['REQUEST_URI']??'', self::$excludeUrl);
    }

    /**
     * vérifie si l'entete User_Agent se trouve dans le tableau self::$userAgent
     * User_Agent blacklisté retourne True, sinon False
     * @return bool
     */
    public static function userAgentIsBlackListed($server): bool
    {
        return self::matchPattern($server['HTTP_USER_AGENT']??'', self::$userAgent);
    }


    /**
     * converti l'ip en host et vérifira s'il est dans la liste blanche $hostNameWhiteList
     * si l'Ip appartient a un host reconnu, retoure True, sinon false
     * @return bool
     */
    public static function hostNameIsWhiteListed($server): bool
    {
        $hostName = gethostbyaddr($server['REMOTE_ADDR']??'');
        return self::matchPattern($hostName, self::$hostNameWhiteList);
    }

    /**
     * vérifie si l'entete Referer se trouve dans le tableau self::$refererBlackList
     * Referer blacklisté retourne True, sinon False
     * @return bool
     */
    public static function refererIsBlackListed($server): bool
    {
        return self::matchPattern($server['HTTP_REFERER']??'', self::$refererBlackList);
    }

    /**
     * ecrit dans htacces d'apache pour bloquer l'ip
     */

    public static function addIpInBlackList(): void
    {
        if (self::$test) {
            die(sprintf('Ip %s ajoutée au fichier %s', $_SERVER['REMOTE_ADDR'], self::FILENAME));
        }
        $homepage = "\r\nDeny from " . $_SERVER['REMOTE_ADDR'];
        file_put_contents(self::FILENAME, $homepage, FILE_APPEND);
    }

    /**
     * modifie le header, pas forcement utile, mais visible dans les logs apache
     */
    public static function header(): void
    {
        header('Status: 666 El Diablo');
    }

    /**
     * @param $server
     *
     * @return bool
     */
    private static function matchPattern($server, $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (substr($pattern, 0, 1) != '/') {
                $pattern = '/' . $pattern;
            }
            if (substr($pattern, -1, 1) != '/') {
                $pattern .= '/';
            }
            if ( preg_match($pattern, $server) == 1) {
                return true;
            }
        }
        return false;
    }
}