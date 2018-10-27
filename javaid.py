#!/usr/bin/env python
# -*- coding:utf-8 -*-
# java source danger function identify prog
# Auth by Cryin'

import re
import os
import optparse
import sys
from lxml.html import etree

'''
XXE:
    "SAXReader",
    "DocumentBuilder",
    "XMLStreamReader",
    "SAXBuilder",
    "SAXParser",
    "XMLReader",
    "SAXSource",
    "TransformerFactory",
    "SAXTransformerFactory",
    "SchemaFactory",
    "Unmarshaller",
    "XPathExpression"

JavaObjectDeserialization:
    "readObject",
    "readUnshared",
    "Yaml.load",
    "fromXML",
    "ObjectMapper.readValue",
    "JSON.parseObject"
SSRF:
    "HttpClient",
    "URL",
    "HttpURLConnection"
FILE:
    "MultipartFile",
    "createNewFile",
    "FileInputStream"
Autobinding:
    "@SessionAttributes",
    "@ModelAttribute"
URL-Redirect:
    "sendRedirect",
    "forward",
    "setHeader"
EXEC:
    "getRuntime.exec",
    "ProcessBuilder.start",
    "GroovyShell.evaluate"

 '''

class javaid(object):
    def __init__(self,dir):

        self._function = ''
        self._fpanttern = ''
        self._line = 0
        self._dir = dir
        self._filename = ''
        self._vultype = ''
        self.cur_id = ''

    def _run(self):
        try:
            self.banner()
            self.handlePath(self._dir)
            #print "[-]【JavaID】identify danger function Finished!"    
        except:
            raise

    def getJAVAPath(self, filepath):
        try:
            pattern = re.compile(r'.*/src/main/java/')
            tmpClassName = re.sub(pattern, '', filepath)
            tmpClassName = tmpClassName.replace("/", ".")

            tmpjavaPath = re.sub('\\.[^\\.]*\\.java', '',tmpClassName)

            #print ("debug --- %s -- %s -- %s" % (tmpClassName, tmpjavaPath, str(re.search(file_pattern, tmpClassName))))
            if self.inner_class == '':
                javaPath = tmpjavaPath + "." + self.cur_class
            else:
                javaPath = tmpjavaPath + "." + self.cur_class + "." + self.inner_class

            pattern = re.compile(r'.*org.onosproject')
            javaPath = re.sub(pattern, 'org.onosproject', javaPath)

            return javaPath
        except:
            return filepath

    # def report_id(self,vul):
    #     self.cur_id = self._filename
        # print "[+]【"+vul+"】identify danger function ["+self._function+"] in file "+self._filename,

    def report_line(self):
        #print "[" + self._function + "]  " + self.getJAVAPath(self._filename) + "@"+ str(self._line)
        javaPath = self.getJAVAPath(self._filename)
        #print ("[%s] class name: %s, method name: %s, inner class: %s, java path: %s" % (self._function, self.cur_class, self.cur_method, self.inner_class, javaPath))
        print ( "[%s] %s#%s@{%s-%s}" %(self._function, javaPath, self.cur_method, self.start_line, self.end_line))

    def handlePath(self, path):
        dirs = os.listdir(path) 

        for d in dirs:
            subpath = os.path.join(path, d) 
            if os.path.isfile(subpath):
                if os.path.splitext(subpath)[1] == '.java' or os.path.splitext(subpath)[1] == '.xml':
                    self._filename =subpath
                    self.handleFile(subpath)  
            else:
                self.handlePath(subpath) 
    
    def handleFile(self, fileName):
        #print 'begin read file:' + fileName
        f = open(fileName, 'r') 
        self._line = 0
        content = f.read()
        content=self.remove_comment(content)
        self.check_regexp(content)

        f.close() 
        #print 'read over file:' + fileName
        #print '------------------------'

    def function_search_line(self, expPattern):
        methodFullPattern = re.compile('\\s{0,}(public|private|protected)\\s{0,}(static|synchronized|final|\s){0,}\\s{0,}([a-zA-Z0-9<>\\[\\]\\.,]){1,}\\s{0,}([a-zA-Z0-9]){1,}\\s?\\(')
        methodPreffixPattern = re.compile('\\s{0,}(public|private|protected)\\s{0,}(static|synchronized|final|\s){0,}\\s{0,}([\\w<>,\\.\\[\\]]+)\\s{0,}')

        classFullPattern = re.compile('\\s{0,}(public|private|protected)\\s{0,}(static|synchronized|final){0,}\\s{0,}(class)\\s{0,}([a-zA-Z0-9]){1,}')
        classPreffixPattern = re.compile('\\s{0,}(public|private|protected)\\s{0,}(static|synchronized|final){0,}\\s{0,}(class)\\s{0,}')

        self.cur_method = ''
        self.cur_class = ''
        self.inner_class = ''

        fl = open(self._filename, 'r') 
        self._line = 0

        importregexp = "import\s[^;]*;"
        exp_pattern = re.compile(importregexp)


        #print "function_search_line"+self._filename
        while True:
            line = fl.readline() 
            if not line:  
                #print "flclose"+str(self._line)
                break

            self._line += 1

            if exp_pattern.search(line):
                continue

            # match class name or inner class name
            if re.match(classFullPattern, line):
                tmpClassName = re.search(classFullPattern, line).group(0)

                if self.cur_class == '':
                    #print "debug --- " + str(re.search(classFullPattern, line).group(0)) + '   ---   ' + line
                    self.cur_class = re.sub(classPreffixPattern, '', tmpClassName)
                else:
                    self.inner_class = re.sub(classPreffixPattern, '', tmpClassName)

                continue

            # match method name
            if re.match(methodFullPattern, line):
                tmpMethodName = re.search(methodFullPattern, line).group(0)
                self.cur_method = re.sub(methodPreffixPattern, '', tmpMethodName)[:-1]

            if expPattern.search(line):
                self.start_line = self._line
                self.end_line = self._line

                while line.find(";") == -1 and line[-3:].find("{") == -1:
                    line = fl.readline()
                    self._line += 1
                    self.end_line += 1
            #if self._function in line:
                #print 'find danger function on line :' + str(line)
                #print ("_function %s --- line %s ---" % (self._function, line[:-1]))
                self.report_line()
                continue

        fl.close()

    def regexp_search(self,rule_dom,content):

        regmatch_dom = rule_dom[0].xpath("regmatch")
        regexp_doms = regmatch_dom[0].xpath("regexp") if regmatch_dom != None else []
        for regexp_dom in regexp_doms:
                exp_pattern = re.compile(regexp_dom.text)
                if exp_pattern.search(content):
                    #print "identify sfunction is : "+self._function
                    self.cur_id = self._filename

                    #self.report_id(self._vultype)
                    self.function_search_line(exp_pattern)

        return True

    def check_regexp(self, content):
        if not content:
            return
        self._xmlstr_dom = etree.parse('regexp.xml')
        javaid_doms = self._xmlstr_dom.xpath("javaid")
        for javaid_dom in javaid_doms:
            self._vultype =javaid_dom.get("vultype")
            #print "vul_type "+self._vultype
            function_doms = javaid_dom.xpath("function")
            for function_dom in function_doms:
                rule_dom = function_dom.xpath("rule")
                self._function =rule_dom[0].get("name")
                self.regexp_search(rule_dom,content)
                #print "check_regexp search ..."
        return True
        
    def remove_comment(self,content):
        return content
    def banner(self):
        #print "[-]【JavaID】 Danger function identify tool"
        pass


if __name__ == '__main__':
    parser = optparse.OptionParser('usage: python %prog [options](eg: python %prog -d /user/java/demo)')
    parser.add_option('-d', '--dir', dest = 'dir', type = 'string', help = 'source code file dir')

    (options, args) = parser.parse_args()

    if options.dir == None or options.dir == "":
        parser.print_help()
        sys.exit()
    dir =options.dir
    javaidentify = javaid(dir)
    javaidentify._run()

