require 'pry'
require 'javaobs'

fin = File.open("./weird.qpdata","rb")
java1 = Java::ObjectInputStream.new fin

binding.pry