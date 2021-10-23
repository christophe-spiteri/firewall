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
namespace ClsScript;

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
            die($log);
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
        if (self::ipIsWhiteListed()) {
            self::log('IP en liste blanche');
            return;
        }

        if (self::hostNameIsWhiteListed()) {
            self::log('HostName en liste Blanche');
            return;
        }

        if (self::urlIsBlackListed()) {
            self::addIpInBlackList();
            self::header();
            self::log('addIpInBlackList urlIsBlackListed');
            die('');
        }

        if (self::userAgentIsBlackListed()) {
            self::addIpInBlackList();
            self::header();
            self::log('addIpInBlackList userAgentIsBlackListed');
            die('');
        }

        if (self::refererIsBlackListed()) {
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
    private static function ipIsWhiteListed(): bool
    {
        foreach (self::$whiteListIp as $ip) {
            if ($ip == substr($_SERVER['REMOTE_ADDR'], 0, strlen($ip))) {
                return true;
            }
        }
        return false;
    }

    /**
     * vérifié si l'url commence par les ip du tableau self::$excludeUrl
     * Ip blacklistée retourne True, sinon False
     * @return bool
     */
    private static function urlIsBlackListed(): bool
    {
        $uri = $_SERVER['REQUEST_URI'];
        if ($uri == '\\') {
            return false;
        }
        foreach (self::$excludeUrl as $urlExclue) {
            if (strstr($uri, $urlExclue) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * vérifie si l'entete User_Agent se trouve dans le tableau self::$userAgent
     * User_Agent blacklisté retourne True, sinon False
     * @return bool
     */
    private static function userAgentIsBlackListed(): bool
    {
        foreach (self::$userAgent as $agent) {
            if (isset($_SERVER['HTTP_USER_AGENT']) and strstr($_SERVER['HTTP_USER_AGENT'], $agent) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * converti l'ip en host et vérifira s'il est dans la liste blanche $hostNameWhiteList
     * si l'Ip appartient a un host reconnu, retoure True, sinon false
     * @return bool
     */
    private static function hostNameIsWhiteListed(): bool
    {
        $hostName = gethostbyaddr($_SERVER['REMOTE_ADDR']);
        foreach (self::$hostNameWhiteList as $name) {
            if (strstr($hostName, $name) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * vérifie si l'entete Referer se trouve dans le tableau self::$refererBlackList
     * Referer blacklisté retourne True, sinon False
     * @return bool
     */
    private static function refererIsBlackListed(): bool
    {
        foreach (self::$refererBlackList as $referer) {
            if (isset($_SERVER['HTTP_REFERER']) and strstr($_SERVER['HTTP_REFERER'], $referer) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * ecrit dans htacces d'apache pour bloquer l'ip
     */

    private static function addIpInBlackList(): void
    {
        $homepage = "\r\nDeny from " . $_SERVER['REMOTE_ADDR'];
        file_put_contents(self::FILENAME, $homepage, FILE_APPEND);
    }

    /**
     * modifie le header, pas forcement utile, mais visible dans les logs apache
     */
    private static function header(): void
    {
        header('Status: 666 El Diablo');
    }
}