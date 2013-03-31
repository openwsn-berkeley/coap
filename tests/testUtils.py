import logging
import os
import inspect

#============================ utils ===========================================

class NullHandler(logging.Handler):
   def emit(self,record):
       pass

def getMyLoggerName():
    frame,filename,line_number,function_name,lines,index=\
       inspect.getouterframes(inspect.currentframe())[1]
    
    filename = os.path.split(filename)[1]
    filename = filename.split('.')[0]
    
    return filename
