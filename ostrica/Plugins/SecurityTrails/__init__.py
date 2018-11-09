#-------------------------------------------------------------------------------
# Name:         OSTrICa - Open Source Threat Intelligence Collector
#               SecurityTrails plugin
#
# Purpose:	Collection and visualization of Threat Intelligence data
#
# Author:      	deCade
#
# Created:     	08/11/2018
# Licence:     	This file is part of OSTrICa.
#
#       OSTrICa is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	OSTrICa is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with OSTrICa. If not, see <http://www.gnu.org/licenses/>.
#
# Warnings:
#
#       This program utilizes SecurityTrails' basic API plan. As such, an API
#       key is required (change cfg.py file under 'utilities' subdir), and, due
#       to quota limitations, the plugin is relegated to whois history only, as
#       of now. This is the only plugin (as of 08/11/2018) that is called when
#       a 'history' search is initiated. Unless you are on a paid plan, please
#       do not use too liberally.
#-------------------------------------------------------------------------------
import sys
import string
import socket
import json
import requests
import time

from ostrica.utilities.cfg import Config as cfg

extraction_type = [cfg.intelligence_type['history']]
enabled = True
version = 0.1
developer = 'deCade'
description = 'Plugin used to collect information about IPs and domains on SecurityTrails'
visual_data = False

class SecurityTrails:

    def __init__(self):
        self.securitytrails_host = 'www.securitytrails.com'
        self.intelligence = {}
        self.json_response = ''
        pass

    def __del__(self):
        if cfg.DEBUG:
            print 'cleanup SecurityTrails...'
        self.intelligence = {}

    def fill_intelligence_dictionary(self, intel):
        self.intelligence['history'] = intel

    def extract_intelligence(self, typology, intel):
        if typology == 'history':
            returned_intel = json.loads(requests.get('https://api.securitytrails.com/v1/%s/%s/whois' % (typology, intel), params = { 'apikey' : cfg.security_trails_api }).text)
            self.fill_intelligence_dictionary(returned_intel)
        #elif typology == 'domain':
            #returned_intel = json.loads(requests.get('https://api.securitytrails.com/v1/history/%s/dns/a' % (intel), params = { 'apikey' : cfg.security_trails_api }).text)
            #self.fill_intelligence_dictionary(returned_intel)

        return self.intelligence

def run(intelligence, extraction_type):
    if cfg.DEBUG:
        print 'Running SecurityTrails() on %s' % intelligence

    intel_collector = SecurityTrails()
    #if extraction_type == cfg.intelligence_type['ip']:
        #if intel_collector.extract_intelligence('ip', intelligence) is not None:
            #collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            #del intel_collector
            #return collected_intel
    #elif extraction_type == cfg.intelligence_type['domain']:
        #if intel_collector.extract_intelligence('domain', intelligence) is not None:
            #collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            #del intel_collector
            #return collected_intel
    if extraction_type == cfg.intelligence_type['history']:
        if intel_collector.extract_intelligence('history', intelligence) is not None:
            collected_intel = extracted_information(extraction_type, intel_collector.intelligence)
            del intel_collector
            return collected_intel

def extracted_information(extraction_type, intelligence_dictionary):
    return {'extraction_type': extraction_type, 'intelligence_information':intelligence_dictionary}

def data_visualization(nodes, edges, json_data):
    if json_data['plugin_name'] == 'SecurityTrails':
        visual_report = SecurityTrailsVisual(nodes, edges, json_data)
        return visual_report.nodes, visual_report.edges
    else:
        return nodes, edges

# MAY CHANGE IN FUTURE ITERATIONS
class SecurityTrailsVisual:

    def __init__(self, ext_nodes, ext_edges, intel):
        self.nodes = ext_nodes
        self.edges = ext_edges
        self.json_data = intel
        self.visual_report_dictionary = {}
        self.origin = ''
        self.color = '#ffe033'
        if self.parse_intelligence() != False:
            self.parse_visual_data()

    def parse_intelligence(self):
        domains = []
        ips = []
        history = []

        if self.json_data['intelligence'] is None:
            return False

        if 'domains' in self.json_data['intelligence']['intelligence_information']:
            domains = self.json_data['intelligence']['intelligence_information']['domains']

        if 'ips' in self.json_data['intelligence']['intelligence_information']:
            ips = self.json_data['intelligence']['intelligence_information']['ips']

        if 'history' in self.json_data['intelligence']['intelligence_information']:
            history = self.json_data['intelligence']['intelligence_information']['history']

        if self.json_data['requested_intel'] not in self.visual_report_dictionary.keys():
            self.visual_report_dictionary[self.json_data['requested_intel']] = {'SecurityTrails': [{'domains': domains}, {'ips': ips}, {'history': history}]}
        else:
            self.visual_report_dictionary[self.json_data['requested_intel']].update({'SecurityTrails': [{'domains': domains}, {'ips': ips}, {'history': history}]})

        self.origin = self.json_data['requested_intel']
        if self.origin not in self.edges.keys():
            self.edges.setdefault(self.origin, [])

    def parse_visual_data(self):
        for intel in self.visual_report_dictionary[self.origin]['SecurityTrails']:
            for key, value in intel.iteritems():
                if key == 'domains':
                    self._manage_securitytrails_domains(value)
                elif key == 'ips':
                    self._manage_securitytrails_ips(value)

    def _manage_securitytrails_domains(self, domains):
        size = 30
        for domain in domains:
            if domain in self.nodes.keys():
                self.nodes[domain] = (self.nodes[domain][0] + 5, self.nodes[domain][1], self.nodes[domain][2])
            else:
                self.nodes[domain] = (size, self.color, 'associated domain')

            if domain not in self.edges[self.origin]:
                self.edges[self.origin].append(domain)

    def _manage_securitytrails_ips(self, ips):
        size = 30
        for ip in ips:
            if ip in self.nodes.keys():
                self.nodes[ip] = (self.nodes[ip][0] + 5, self.nodes[ip][1], self.nodes[ip][2])
            else:
                self.nodes[ip] = (size, self.color, 'ip')

            if ip not in self.edges[self.origin]:
                self.edges[self.origin].append(ip)
