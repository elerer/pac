/*   Global Pac File   */
'use strict';
function getPort(url)
{
    var port;
    var base_str = url.split("/")[2];
    var str_after_userpass = base_str.split("@")[1];

    if (str_after_userpass) {
        port = parseInt(str_after_userpass.split(":")[1]);
    }
    else {
        port = parseInt(base_str.split(":")[1]);
    }
    if(isNaN(port)) {
        return 80;
    }
    return port;
}

function ip2num(ip)
{
    var d = ip.split('.');
    return ((((((+d[0])*256)+(+d[1]))*256)+(+d[2]))*256)+(+d[3]);
}

function isInRange(ip, range_ip1, range_ip2)
{
    var ip_num = ip2num(ip);
    return (ip_num >= ip2num(range_ip1) && ip_num <= ip2num(range_ip2));
}

function FindProxyForURL(url, host) {
    /* Normalize the URL for pattern matching */
    url = url.toLowerCase();
    host = host.toLowerCase();

    if (shExpMatch(host, "*.cpsserv.com")) {
        
        if (url.substring(0, 5) === 'http:' )
        {
            return 'PROXY 84.39.153.38:80; PROXY 84.39.152.38:80; ';
        }
        if (url.substring(0, 6) === 'https:' )
        {
            return 'PROXY 84.39.153.38:80; PROXY 84.39.152.38:80; ' ;
        }
        
    }

    var hostIP = false;
    if (isResolvable(host))
    {
        hostIP = dnsResolve(host);
    }

    /* start DIRECT section */
    /* Don't proxy specific hostname */
    if (
        (host === "apple.com") || dnsDomainIs(host, ".apple.com") ||
        (host === "get.adobe.com") || dnsDomainIs(host, ".get.adobe.com") ||
        (host === "crl.comodo.net") || dnsDomainIs(host, ".crl.comodo.net") ||
        (host === "crl.comodoca.com") || dnsDomainIs(host, ".crl.comodoca.com") ||
        (host === "ocsp.comodoca.com") || dnsDomainIs(host, ".ocsp.comodoca.com") ||
        (host === "live.com") || dnsDomainIs(host, ".live.com") ||
        (host === "microsoft.com") || dnsDomainIs(host, ".microsoft.com") ||
        (host === "swebkiss.is-teledata.com") || dnsDomainIs(host, ".swebkiss.is-teledata.com") ||
        (host === "webfinanceopen.teledata.de") || dnsDomainIs(host, ".webfinanceopen.teledata.de") ||
        (host === "webex.com") || dnsDomainIs(host, ".webex.com") ||
        (host === "windowsupdate.com") || dnsDomainIs(host, ".windowsupdate.com") ||
        (host === "wustat.windows.com") || dnsDomainIs(host, ".wustat.windows.com") ||
        (host === "auth.gfx.ms") || dnsDomainIs(host, ".auth.gfx.ms") ||
        (host === "geo.kaspersky.com") || dnsDomainIs(host, ".geo.kaspersky.com") ||
        (host === "kavdumps.kaspersky.com") || dnsDomainIs(host, ".kavdumps.kaspersky.com") ||
        (host === "crl.verisign.net") || dnsDomainIs(host, ".crl.verisign.net") ||
        (host === "pluto-webapp-prod-us-static.s3.amazonaws.com") || dnsDomainIs(host, ".pluto-webapp-prod-us-static.s3.amazonaws.com") ||
        (host === "cloudfront.net") || dnsDomainIs(host, ".cloudfront.net") ||
        (host === "amazonaws.com") || dnsDomainIs(host, ".amazonaws.com") ||
        (host === "googleapis.com") || dnsDomainIs(host, ".googleapis.com") ||
        (host === "*.google.com") || dnsDomainIs(host, ".*.google.com") ||
        (host === "google.com") || dnsDomainIs(host, ".google.com") ||
        (host === "www.google.com") || dnsDomainIs(host, ".www.google.com") ||
        (host === "dropbox.com") || dnsDomainIs(host, ".dropbox.com") ||
        (host === "slack-msgs.com") || dnsDomainIs(host, ".slack-msgs.com") ||
        (host === "slack-imgs.com") || dnsDomainIs(host, ".slack-imgs.com") ||
        (host === "slack-redir.net") || dnsDomainIs(host, ".slack-redir.net") ||
        (host === "slack-edge.com") || dnsDomainIs(host, ".slack-edge.com") ||
        (host === "slack-core.com") || dnsDomainIs(host, ".slack-core.com") ||
        (host === "slack.com") || dnsDomainIs(host, ".slack.com") ||
        (host === "icloud.com") || dnsDomainIs(host, ".icloud.com") ||
        (host === "ynet.co.il") || dnsDomainIs(host, ".ynet.co.il") ||
        false)
    {
        return 'DIRECT';
    }

    /* Don't proxy specific wildcard host */
    if (
        shExpMatch(host,"*.googleapis.com") ||
        shExpMatch(host,"*.amazonaws.com") ||
        shExpMatch(host,"*.cloudfront.net") ||
        shExpMatch(host,"*.dropbox.com") ||
        false)
    {
        return 'DIRECT';
    }

    /* Don't proxy specific url */
    if (
        false)
    {
        return 'DIRECT';
    }

    if (hostIP) {
        /* Don't proxy specific ip */
        if (
            false)
        {
            return 'DIRECT';
        }

        /* Don't proxy specific wildcard ip */
        if (
            false)
        {
            return 'DIRECT';
        }

        /* Don't proxy specific ip range */
        if (
            false)
        {
            return 'DIRECT';
        }
    }
    /* end DIRECT section */


    /* start local proxy section */
    /* Don't proxy specific hostname */
    if (
        false)
    {
        return ' DIRECT';
    }

    /* Don't proxy specific wildcard host */
    if (
        false)
    {
        return ' DIRECT';
    }

    /* Don't proxy specific url */
    if (
        false)
    {
        return ' DIRECT';
    }

    if (hostIP) {
        /* Don't proxy specific ip */
        if (
            false)
        {
            return ' DIRECT';
        }

        /* Don't proxy specific wildcard ip */
        if (
            false)
        {
            return ' DIRECT';
        }

        /* Don't proxy specific ip range */
        if (
            false)
        {
            return ' DIRECT';
        }
    /* end local proxy section */

        /* Don't proxy non-routable addresses (RFC 3330) */
        if (isInNet(hostIP, '0.0.0.0', '255.0.0.0') ||
            isInNet(hostIP, '10.0.0.0', '255.0.0.0') ||
            isInNet(hostIP, '127.0.0.0', '255.0.0.0') ||
            isInNet(hostIP, '169.254.0.0', '255.255.0.0') ||
            isInNet(hostIP, '172.16.0.0', '255.240.0.0') ||
            isInNet(hostIP, '192.0.2.0', '255.255.255.0') ||
            isInNet(hostIP, '192.88.99.0', '255.255.255.0') ||
            isInNet(hostIP, '192.168.0.0', '255.255.0.0') ||
            isInNet(hostIP, '198.18.0.0', '255.254.0.0') ||
            isInNet(hostIP, '224.0.0.0', '240.0.0.0') ||
            isInNet(hostIP, '240.0.0.0', '240.0.0.0'))
        {
            return 'DIRECT';
        }
    }

    /* Don't proxy local hostnames */
    if ( isPlainHostName(host)       ||
         shExpMatch(host, "*.local")    )
    {
        return 'DIRECT';
    }

    /* Do not proxy ports we do not want to handle */
    var port = getPort(url);
    if(port !== 80 && port !== 443)
    {
        return 'DIRECT';
    }
    
    if (url.substring(0, 5) === 'http:' )
    {
        return 'PROXY 84.39.153.38:80; PROXY 84.39.152.38:80; ';
    }
    if (url.substring(0, 6) === 'https:' )
    {
        return 'PROXY 84.39.153.38:80; PROXY 84.39.152.38:80; ' ;
    }
    
    return 'DIRECT';
}
/* Generated for requester: 37.19.117.89   geo: True   site_ip: 37.19.117.91   unavailable_sites: []   on_site: False   trx_id: 2cddaed89e8c4eb1baf7a1bebcaeed42   trx_timestamp: 2018-05-29 10:07:18.214585+00:00 */