#!/usr/bin/env python
# -*- coding: utf-8 -*-

############################################################################################
# sleight.py:   Empire HTTP C2 Redirector Setup Script
# Author:   VIVI | <Blog: thevivi.net> | <Twitter: @_theVIVI> | <Email: gabriel@thevivi.net> 
############################################################################################

import subprocess
import argparse
import time
import sys
import re
import os

# Console colours
W = '\033[0m'     #normal
R = '\033[31m'    #red
T = '\033[93m'    #tan
G = '\033[32m'    #green
LG = '\033[1;32m' #light green

htaccess_template = '''
RewriteEngine On
RewriteCond %{{REQUEST_URI}} ^/({})/?$
RewriteCond %{{HTTP_USER_AGENT}} ^{}?$
RewriteRule ^.*$ http://{}%{{REQUEST_URI}} [P]
RewriteRule ^.*$ {}/? [L,R=302]
'''

def parse_args():

    # Arguments
    parser = argparse.ArgumentParser(description='Empire' +
        ' HTTP C2 Redirector Setup')

    parser.add_argument(
        '-c',
        '--commProfile',    
        help='Path to Empire Communication Profile',
        required=True
    )

    return parser.parse_args()

def shutdown():

   # User shutdown
   print '\n[' + R + '!' + W + '] Exiting.'
   sys.exit()

def convert_profile():

    # Get EmpireC2 Host and Redirect Site
    empireC2 = raw_input(
        '[' + G + '+' + W + '] Empire C2 LHOST: ')
    while empireC2 == '':
        empireC2 = raw_input("[-] Empire C2 LHOST: ")

    redirect = raw_input(
        '[' + G + '+' + W + '] Redirect Site URL: ')
    while redirect == '':
        redirect = raw_input("[-] Redirect Site URL: ")

    # Read CommmProfile
    commProfile = open(args.commProfile, 'r')
    cp_file = commProfile.read()
    commProfile.close()
    print '[' + T + '*' + W + '] Generating mod_rewrite rules...'
    profile = re.sub(r'(?m)^\#.*\n?', '', cp_file).strip('\n')
    
    #GET Request URI(s)
    uri_string = profile.split('|')[0]
    uri = uri_string.replace('\"','').replace(',','|').replace(',','|').strip('/')
    uri = uri.replace('|/','|')

    #User Agent
    user_agent_string = profile.split('|')[1]
    user_agent = user_agent_string.replace(' ','\ ').replace('.','\.').replace('(','\(').replace(')','\)')

    print '[' + LG + '!' + W + '] mod_rewrite rules generated.'
    rules = (htaccess_template.format(uri,user_agent,empireC2,redirect))
    print rules
    return rules

def get_apache():

    # Install apache
    if not os.path.isdir('/etc/apache2/'):
        install = raw_input(
            ('[' + G + '+' + W + '] Apache installation not found' +
             ' in /etc/apache2/. Install now? [y/N] ')
        )
        if install == 'y':
            print '\n[' + T + '*' + W + '] Installing Apache...'
            subprocess.call(['apt-get', 'update'])
            subprocess.call(['apt-get','install','apache2','-y'])
            print '\n[' + LG + '!' + W + '] Apache installed.'
        else:
            sys.exit(('[' + R + '!' + W + '] Exiting. Apache' +
                     ' not installed.'))

def enable_mod_rewrite():

	#Backup apache config file
	if not os.path.isfile("/etc/apache2/apache2.conf.bak"):
		print '\n[' + T + '*' + W + '] Backing up Apache configuration file...'
		subprocess.call(['cp', '/etc/apache2/apache2.conf', '/etc/apache2/apache2.conf.bak'])

	#Edit apache config file
	print '[' + T + '*' + W + '] Enabling mod_rewrite...\n'
	ac1 = open('/etc/apache2/apache2.conf', 'r')
	old_config = ac1.read()
	ac1.close()
	dir_tag = re.compile(r"/var/www/>.*?</Directory", flags=re.DOTALL)
	new_config = dir_tag.sub(lambda match: match.group(0).replace('None','All') ,old_config)
	ac2 = open('/etc/apache2/apache2.conf', 'w')
	ac2.write(new_config)
	ac2.close()

	#Enable mod_rewrite modules
	subprocess.call(['a2enmod', 'rewrite', 'proxy', 'proxy_http'])
	restart = subprocess.Popen(['service', 'apache2', 'restart'], \
		stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	output,error = restart.communicate()
	print output,error

	if 'apache2.service failed' in str(error):
		print '\n[' + R + '!' + W + '] mod_rewrite not enabled.'
		sys.exit(('[' + R + '!' + W + '] Exiting. mod_rewrite could not' +
			' not be enabled.'))
	else:
		print '\n[' + LG + '!' + W + '] mod_rewrite enabled.\n'
		subprocess.call(['service', 'apache2', 'status'])

def write_rules(rules):
	
	# Write rules to .htaccess
	ruleset = str(rules).strip('\n')
	print '\n[' + T + '*' + W + '] Writing rules to /var/www/html/.htaccess'
	htaccess = open('/var/www/html/.htaccess', 'w')
	htaccess.write(ruleset)
	htaccess.close()
	subprocess.call(['chmod', '644', '/var/www/html/.htaccess'])
	print '[' + LG + '!' + W + '] Rules written to /var/www/html/.htaccess\n'
	subprocess.call(['ls', '-la', '/var/www/html/.htaccess'])

	# Restart apache
	print '\n[' + T + '*' + W + '] Restarting Apache...\n'
	subprocess.call(['service', 'apache2', 'restart'])
	subprocess.call(['service', 'apache2', 'status'])
	print '\n[' + LG + '!' + W + '] Apache restarted.'


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
	#Start timer
	start = time.time()

	# Parse args
	args = parse_args()

	#Root check
	if os.geteuid():
		sys.exit('[' + R + '-' + W + ']' +
			' This script must be run as root')

	try:
		rules = convert_profile()
		
		configure = raw_input(
			('[' + G + '+' + W + '] Proceed with redirector setup?' +
				' [y/N] ')
			)

		if configure == 'y':
			get_apache()
			enable_mod_rewrite()
			write_rules(rules)			
		else:
			sys.exit(('[' + R + '!' + W + '] Exiting. Redirector' +
				' not configured.'))

		print '\n[' + LG + '!' + W + ']' + LG + ' Setup complete!' + W \
		, ' You can now test your redirector.'

		# Print runtime
		runtime = str(time.time()-start)
		runtime = runtime[:-5]
		print '[' + T + '*' + W + '] Script runtime: '+ T \
		, runtime, 'seconds'+W

	except KeyboardInterrupt:
		shutdown()