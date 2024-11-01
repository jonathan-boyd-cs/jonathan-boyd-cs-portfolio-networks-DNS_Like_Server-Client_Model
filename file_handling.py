#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Module: file_handling.py
    Author: Jonathan Boyd
    
"""
from io import TextIOWrapper

def file_reader(file_handler : TextIOWrapper) -> str | None :
    """ 
        Function takes a file handler, produced by the python open() function,
        and returns either the next read line or None if eof.<br>
        
        Parmeters:<br>
        - <strong>file_handler</strong>  (<code>TextIOWrapper</code>): the file handle from <code>open()</code> function call.<br>
        
        Returns:<br>
        - <code>str</code> OR <code>None</code>:    next line of file if not eof, else None  
    """
    # eof ?
    #where eof is denoted by a single byte read of an empty string
    readable : bool = (file_handler.read(1) != '')
    #correct the file handler position after eof check
    currentFilePos = file_handler.tell() - 1
    file_handler.seek(currentFilePos, 0)
    if readable:
        #return next data line
        return file_handler.readline()
    else:
        return None