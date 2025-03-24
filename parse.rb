require './lib'
require 'pry'

raw = File.open("./weird.qpdata","rb"){|f| f.read}
#raw = File.open("./test_class_stream.stream","rb"){|f| f.read}
javastream1 = JavaObjectStream.new raw
binding.pry