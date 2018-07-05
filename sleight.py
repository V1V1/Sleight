#!/usr/bin/env python
# -*- coding: utf-8 -*-

############################################################################################
# sleight.py:   Empire HTTP(S) C2 redirector setup script
# Author:   VIVI | <Blog: thevivi.net> | <Twitter: @_theVIVI> | <Email: gabriel@thevivi.net> 
############################################################################################

import subprocess
import argparse
import sys
import re
import os

# Console colours
W = '\033[0m'     #normal
R = '\033[1;31m'  #red
T = '\033[1;93m'  #tan
G = '\033[32m'    #green
LG = '\033[1;32m' #light green

htaccess_template = '''
RewriteEngine On
RewriteCond %{{REQUEST_URI}} ^/({})/?$
RewriteCond %{{HTTP_USER_AGENT}} ^{}?$
RewriteRule ^.*$ http://{}:{}%{{REQUEST_URI}} [P]
RewriteRule ^.*$ {}/? [L,R=302]
'''

def parse_args():

    # Arguments
    parser = argparse.ArgumentParser(description='Empire' +
        ' HTTP(S) C2 redirector setup script')

    parser.add_argument(
        '-c',
        '--commProfile',    
        help='Path to Empire Communication Profile',
        required=True
    )

    parser.add_argument(
        '-r',
        '--redirectDomain',    
        help='Domain bad traffic will be redirected to.',
        required=True
    )

    parser.add_argument(
        '-p',
        '--port',    
        help='Port that the remote C2 is listening on',
        required=False
    )

    parser.add_argument(
        '-i',
        '--ip',    
        help='IP Address of the remote C2 listener',
        required=False
    )

    parser.add_argument(
        '-m',
        '--modeHTTPS',    
        help='HTTPS Listener for redirector? [y/N]',
        required=False
    )

    parser.add_argument(
        '-t',
        '--myDomain',    
        help='Domain name for redirector',
        required=False
    )
    parser.add_argument(
        '-q',
        '--proceed',    
        help='Proceed with configuration of HTTPS Redirector and Cert Deployment [y/N]',
        required=False
    )

    return parser.parse_args()

def shutdown():

   # User shutdown
   print '\n' + R + '[!]' + W + ' Exiting.'
   sys.exit()

def convert_profile():
    # Get LHOST, LPORT and redirect site
    print args.ip
    if args.ip:
	# Get LHOST, LPORT and redirect site
 		LHOST = args.ip
    else:
        LHOST = raw_input(
        '\n' + G + '[+]' + W + ' Empire C2 LHOST: ')
        while LHOST == '':
            LHOST = raw_input("[-] Empire C2 LHOST: ")
 
    if args.port:
		LPORT = args.port
    else:
        LPORT = raw_input(
        G + '[+]' + W + ' Empire C2 LPORT: ')
        while LPORT == '':
            LPORT = raw_input("[-] Empire C2 LPORT: ")

    if args.modeHTTPS:
		HTTPS = args.modeHTTPS
    else:
        HTTPS = raw_input(
        G + '[+]' + W + ' HTTPS listener? [y/N]: ')
        while HTTPS == '':
            HTTPS = raw_input("[-] HTTPS listener? [y/N]: ")

    if args.redirectDomain:
        redirect = args.redirectDomain
    else:
        redirect = raw_input(
        G + '[+]' + W + ' Redirect Site URL: ')
        while redirect == '':
            redirect = raw_input("[-] Redirect Site URL: ")

    commProfile = open(args.commProfile, 'r')
    cp_file = commProfile.read()
    commProfile.close()
    profile = re.sub(r'(?m)^\#.*\n?', '', cp_file).strip('\n')
    
    # GET request URI(s)
    uri_string = profile.split('|')[0]
    uri = uri_string.replace('\"','').replace(',','|').replace(',','|').strip('/')
    uri = uri.replace('|/','|')

    # User agent
    user_agent_string = profile.split('|')[1]
    user_agent = user_agent_string.replace(' ','\ ').replace('.','\.').replace('(','\(').replace(')','\)')
    user_agent = user_agent.rstrip('\"')

    # HTTPS rules
    if HTTPS == 'y':
    	htaccess_template_https = htaccess_template.replace('http', 'https', 1)
    	rules = (htaccess_template_https.format(uri,user_agent,LHOST,LPORT,redirect))
    else:
    	rules = (htaccess_template.format(uri,user_agent,LHOST,LPORT,redirect))
    
    print LG + '\n[!]' + W + ' mod_rewrite rules generated.'
    print rules
    return rules

def get_apache():

    # Install Apache
    if not os.path.isdir('/etc/apache2/'):
        install = raw_input(
            (G + '[+]' + W + ' Apache installation not found' +
             ' in /etc/apache2/. Install now? [y/N] ')
        )
        if install == 'y':
            print '\n' + T + '[*]' + W + ' Installing Apache...\n'
            subprocess.call(['apt-get', 'update','-y'])
            subprocess.call(['apt-get','install','apache2','-y'])
            print LG + '\n[!]' + W + ' Apache installed.'
        else:
            sys.exit((R + '[!]' + W + ' Exiting. Apache' +
                     ' not installed.'))

def get_https_cert():

    # Generate HTTPS certificate
    print '\n' + T + '[*]' + W + ' Generating Let\'s Encrypt HTTPS certificate...'
    
    if not args.myDomain:
        domain = raw_input(
            '\n' + G + '[+]' + W + ' Redirector domain (e.g. example.com): ')
        while domain == '':
            domain = raw_input("[-] Redirector domain (e.g. example.com): ")
    else:
		domain = args.myDomain
    print '\n' + T + '[*]' + W + ' Runnning certbot. This might take some time...\n'
    if not os.path.isfile("./certbot-auto"):
    	subprocess.call(['wget', 'https://dl.eff.org/certbot-auto'])
    subprocess.call(['chmod', 'a+x', './certbot-auto'])
    subprocess.call(['service', 'apache2', 'stop'])
# TODO: add sub domain enumeration here, so news,images,www,static can be fed as a CLI arg and the array is parsed as multiple -d options.
    if args.proceed:
        subprocess.call(['./certbot-auto', 'certonly', '--standalone', '-d', \
    	str(domain), '-d', 'www.'+str(domain), '--register-unsafely-without-email', '--agree-tos', '--non-interactive'])
    
    else:
        subprocess.call(['./certbot-auto', 'certonly', '--standalone', '-d', \
    	str(domain), '-d', 'www.'+str(domain)])
    
    cert_dir = '/etc/letsencrypt/live/'+str(domain)
    if not os.path.isdir(str(cert_dir)):
    	print '\n' + R + '[!]' + W + ' HTTPS certificate for ' \
    	+ T + str(domain) + W + ' not generated.' 
    	sys.exit((R + '[!]' + W + ' Exiting. HTTPS certificate' +
    		' generation failed.'))
    else:
		print LG + '\n[!]' + W + ' HTTPS certificate for ' \
    	+ T + str(domain) + W + ' successfully generated.'
    
    return domain

def mod_rewrite_config(rules):

	# Backup Apache config file
	if not os.path.isfile("/etc/apache2/apache2.conf.bak"):
		print '\n' + T + '[*]' + W + ' Backing up Apache configuration file...'
		subprocess.call(['cp', '/etc/apache2/apache2.conf', '/etc/apache2/apache2.conf.bak'])

	# Edit Apache config file
	print T + '[*]' + W + ' Enabling mod_rewrite...\n'
	ac1 = open('/etc/apache2/apache2.conf', 'r')
	old_config = ac1.read()
	ac1.close()
	dir_tag = re.compile(r"/var/www/>.*?</Directory", flags=re.DOTALL)
	new_config = dir_tag.sub(lambda match: match.group(0).replace('None','All') ,old_config)
	ac2 = open('/etc/apache2/apache2.conf', 'w')
	ac2.write(new_config)
	ac2.close()

	# Enable mod_rewrite modules
	subprocess.call(['a2enmod', 'rewrite', 'proxy', 'proxy_http'])
	
	# HTTPS configuration
	f = re.split("\n", rules)
	if 'https' in f[4]:
		# Get cert
		domain = get_https_cert()
		# Enable HTTPS
		print '\n' + T + '[*]' + W + ' Enabling HTTPS...\n'
		subprocess.call(['a2enmod', 'ssl'])
		subprocess.call(['a2ensite', 'default-ssl.conf'])
		# Backup SSL config file
		if not os.path.isfile("/etc/apache2/sites-enabled/default-ssl.conf.bak"):
			print '\n' + T + '[*]' + W + ' Backing up SSL configuration file...'
			subprocess.call(['cp', '/etc/apache2/sites-enabled/default-ssl.conf', \
				'/etc/apache2/sites-enabled/default-ssl.conf.bak'])

		# Edit SSL config file
		ssl1 = open('/etc/apache2/sites-enabled/default-ssl.conf', 'r')
		old_config = ssl1.read()
		ssl1.close()
		
		ssl_settings = '''
		SSLEngine On
		# Enable Proxy
		SSLProxyEngine On
		# Trust Self-Signed Certificates
		SSLProxyVerify none
		SSLProxyCheckPeerCN off
		SSLProxyCheckPeerName off'''

		ssl_on_tag = re.compile(r"SSL Engine Switch:.*?A self-signed", flags=re.DOTALL)
		new_config = ssl_on_tag.sub(lambda match: \
			match.group(0).replace('SSLEngine on',str(ssl_settings)) ,old_config)
		
		cert_settings = '''#   SSLCertificateFile directive is needed.
		
		# Certificate files for {}
		#SSLCertificateFile      /etc/letsencrypt/live/{}/cert.pem
		SSLCertificateFile      /etc/letsencrypt/live/{}/fullchain.pem
		SSLCertificateKeyFile      /etc/letsencrypt/live/{}/privkey.pem

		#   Server Certificate Chain:'''.format(domain, domain, domain, domain)

		certs_tag = re.compile(r"#   SSLCertificateFile directive is needed..*?#   Server Certificate Chain:", \
			flags=re.DOTALL)
		new_config = certs_tag.sub(str(cert_settings) ,new_config, 1)

		ssl2 = open('/etc/apache2/sites-enabled/default-ssl.conf', 'w')
		ssl2.write(new_config)
		ssl2.close()

	# Restart Apache
	restart = subprocess.Popen(['service', 'apache2', 'restart'], \
		stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	output,error = restart.communicate()
	print output,error

	if 'apache2.service failed' in str(error):
		print '\n' + R + '[!]' + W + ' mod_rewrite not enabled.'
		sys.exit((R + '[!]' + W + ' Exiting. mod_rewrite could not' +
			' not be enabled.'))
	else:
		print LG + '\n[!]' + W + ' mod_rewrite enabled.\n'

def write_rules(rules):
	
	# Write rules to .htaccess
	ruleset = str(rules).strip('\n')
	htaccess = open('/var/www/html/.htaccess', 'w')
	htaccess.write(ruleset)
	htaccess.close()
	subprocess.call(['chmod', '644', '/var/www/html/.htaccess'])
	print LG + '[!]' + W + ' mod_rewrite rules written to /var/www/html/.htaccess\n'
	subprocess.call(['ls', '-la', '/var/www/html/.htaccess'])

	# Restart Apache
	print '\n' + T + '[*]' + W + ' Restarting Apache...\n'
	subprocess.call(['service', 'apache2', 'restart'])
	print LG + '[!]' + W + ' Apache restarted.\n'

# Main section
if __name__ == "__main__":

	print """                         
	                       .------.
	    .------.           |A .   |
	    |A_  _ |    .------; / \  |
	    |( \/ )|-----. _   |(_ _) |
	    | \  / | /\  |( )  |  I  A|
	    |  \/ A|/  \ |___) |------'
	    `-----+'\  / | Y  A|
	          |  \/ A|-----'
	          `------'
	     ▄▄ ▝▜       ▝      ▐    ▗  
	    ▐▘ ▘ ▐   ▄▖ ▗▄   ▄▄ ▐▗▖ ▗▟▄ 
	    ▝▙▄  ▐  ▐▘▐  ▐  ▐▘▜ ▐▘▐  ▐  
	      ▝▌ ▐  ▐▀▀  ▐  ▐ ▐ ▐ ▐  ▐  
	    ▝▄▟▘ ▝▄ ▝▙▞ ▗▟▄ ▝▙▜ ▐ ▐  ▝▄ 
	                     ▖▐         
	                     ▝▘         
	"""

	# Parse args
	args = parse_args()

	# Root check
	if os.geteuid():
		sys.exit('\n' + R + '[!]' + W +
			' This script must be run as root')

	try:
		rules = convert_profile()
		
		configure = args.proceed

		if configure == 'y':
			get_apache()
			mod_rewrite_config(rules)
			write_rules(rules)			
		else:
			sys.exit((R + '[!]' + W + ' Exiting. Redirector' +
				' not configured.'))

		print LG + '[!] Setup complete!' + W
		print LG + '\n[!]' + W + ' You can now test your redirector.\n'

	except KeyboardInterrupt:
		shutdown()
