#!/usr/bin/env python
# -*- coding:utf-8 -*-

import re
import os
import optparse
import sys
from lxml.html import etree

class jsid(object):
    def __init__(self, dir, checker = None, config = None):
        self.dir = dir

        if checker:
            self.checker = checker
        else:
            self.checker = self.regMatcher
        if config:
            self.getConfiguration = config
        else:
            self.getConfiguration = self.getXMLConfiguration

    @staticmethod
    def regMatcher(target_file, reg_dict):
        lines = []
        with open(target_file) as f:
            lines = f.readlines()
        
        #print reg_dict
        for line_index in range(len(lines)):
            for vultype, rule_list in reg_dict.iteritems():
                for reg in rule_list:
                    if reg[1].search(lines[line_index]):
                        print "[{vultype:<5}, {vultype_desc}] {file_path}: {line_number}".format(vultype = vultype, vultype_desc = reg[0], file_path = target_file, line_number = line_index)

    @staticmethod
    def getXMLConfiguration(path = "regexp.xml"):
        config = {}

        xml_dom = etree.parse(path)
        jsid_doms = xml_dom.xpath("jsid")

        try:
            for jsid_dom in jsid_doms:
                vultype = jsid_dom.get("vultype")
                #print vultype
                config[vultype] = []

                rule_doms = jsid_dom.xpath("rule")
                for rule_dom in rule_doms:
                    regexp_dom = rule_dom.xpath("regexp")[0]
                    value = [rule_dom.get("name"), re.compile(regexp_dom.text)]
                    config[vultype].append(value)
        except:
            print "Error when parsing xml file. Please check the format"
        
        return config

    def getFileList(self, path):
        dirs = os.listdir(path)

        file_list = []

        for d in dirs:
            subpath = os.path.join(path, d) 
            if d.__contains__("test"):
                continue
            if os.path.isfile(subpath):
                fname, ext = os.path.splitext(subpath)
                if ext == '.js':
                    file_list.append(subpath)
                    # self.handleFile(subpath)
            else:
                file_list += self.getFileList(subpath)

        return file_list

    def run(self, config_file):
        try:
            fileList = self.getFileList(self.dir)
            config = self.getConfiguration(config_file)
            
            for f in fileList:
                self.checker(f, config)
        except:
            raise

if __name__ == '__main__':
    parser = optparse.OptionParser('usage: python %prog [options](eg: python %prog -d /user/java/demo)')
    parser.add_option('-d', '--dir', dest = 'dir', type = 'string', help = 'source code file dir')
    parser.add_option('-c', '--config', dest = 'config_file', type = 'string', help = 'configuration file path')

    (options, args) = parser.parse_args()

    if options.dir == None or options.dir == "":
        parser.print_help()
        sys.exit()

    if options.config_file == None or options.config_file == "":
        config_file = "regexp.xml"
    else:
        config_file = options.config_file

    dir = options.dir
    jsidentify = jsid(dir)
    jsidentify.run(config_file)
