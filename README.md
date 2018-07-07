# Sleight
Empire HTTP(S) C2 redirector setup script.

### Usage:
Sleight can be used in 3 ways:

#### 1) Setup HTTP Redirector:
1. Run Sleight and feed it an Empire communication profile.
2. Input your Empire C2's IP address and listening port.
3. Say no to the HTTPS prompt.
4. Input a site to redirect all invalid requests to.
5. Start an Empire HTTP listener with the 'Host' property set to the domain of your redirector.

##### HTTP Redirectors reference:
* https://thevivi.net/2017/11/03/securing-your-empire-c2-with-apache-mod_rewrite/

#### 2) Setup HTTPS Redirector:
1. Run Sleight and feed it an Empire communication profile.
2. Input your Empire C2's IP address and listening port.
3. Say yes to the HTTPS prompt.
4. Input a site to redirect all invalid requests to.
5. Input the domain assigned to your redirector (for generation of a Let's Encrypt certificate).
6. Agree to the certbot prompts.
7. Start an Empire HTTPS listener with the 'Host' property set to the domain of your redirector.

##### HTTPS Redirector Setup Notes:
* Certificate generation will only work once your redirector's domain has propagated successfully.
* You'll need DNS entries for both DOMAIN.com and www<nolink>.<nolink>DOMAIN.com for your redirector's domain.
* You can use the default HTTPS certificates Empire comes with (located in the '/empire/data/' directory) for the 'CertPath' property when starting a HTTPS listener on your C2 server.

##### HTTPS Redirectors reference:
* https://bluescreenofjeff.com/2018-04-12-https-payload-and-c2-redirectors/
* https://posts.specterops.io/automating-apache-mod-rewrite-and-cobalt-strike-malleable-c2-profiles-d45266ca642

#### 3) Rules only (no setup):
If you only want to use Sleight to convert an Empire communication profile into mod_rewrite rules and not setup your redirector, simply feed it a communication profile and say no to the "proceed with setup" prompt.

#### 4) CLI arguments:
If you want to use Sleight non interactively, command line arguments can be found in the default output. Any value not defined at launch will be prompted for during execution.

### Examples:
$ sudo python sleight.py -c profiles/default.txt

$ sudo python sleight.py --modeHTTPS=y --myDomain=3xample.com --ip=My.C2.IP.Address --redirectDomain=example.com -c profiles/default.txt --proceed=n --port=80
