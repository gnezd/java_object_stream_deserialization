require 'pry'

STREAM_MAGIC = "\xac\xed".b
STREAM_VERSION = "\x00\x05".b
TC_NULL = "\x70".b
TC_REFERENCE = "\x71".b
TC_CLASSDESC = "\x72".b
TC_OBJECT = "\x73".b
TC_STRING = "\x74".b
TC_ARRAY = "\x75".b
TC_CLASS = "\x76".b
TC_BLOCKDATA = "\x77".b
TC_ENDBLOCKDATA = "\x78".b
TC_RESET = "\x79".b
TC_BLOCKDATALONG = "\x7A".b
TC_EXCEPTION = "\x7B".b
TC_LONGSTRING = "\x7C".b
TC_PROXYCLASSDESC = "\x7D".b
TC_ENUM = "\x7E".b
baseWireHandle = "\x7E\x00\x00".b
SC_WRITE_METHOD = "\x01".b # if SC_SERIALIZABLE
SC_BLOCK_DATA = "\x08".b    # if SC_EXTERNALIZABLE
SC_SERIALIZABLE = "\x02".b
SC_EXTERNALIZABLE = "\x04".b
SC_ENUM = "\x10".b
class JavaObjectStream
  attr_accessor :objects
  def initialize(raw)
    @raw = raw.force_encoding Encoding::ASCII_8BIT
    @ptr = 0

    @handles = [] # reference handles

    raise "ACED0005 header not found" unless raw[0..3] == STREAM_MAGIC + STREAM_VERSION
    @ptr += 4

    read_content while @ptr < raw.size-1
  end

# Read all sorts of objects and blockdata
# Return type and data
# May be used recursively. Behavior determined by the flag byte
  def read_content(expectation = nil)
    content_flag = @raw[@ptr]
    while content_flag == "\0".b
      @ptr += 1
      content_flag = @raw[@ptr]
    end
    puts "Reading at #{@ptr} having content_flag 0x#{"%2x" % content_flag.bytes[0]}"
    if expectation.is_a? String
      raise "Expecting 0x#{"%2x" % expectation.bytes[0]} at #{@ptr} but got 0x#{"%2x" % content_flag.bytes[0]} instead" if (expectation != content_flag)
    elsif expectation.is_a? Array
      raise "Expecting #{expectation.map{|exp| "0x%2x"%exp.bytes[0]}} at #{@ptr} but got 0x#{"%2x" % content_flag.bytes[0]} instead" unless (expectation.include? content_flag)
    end
    @ptr += 1

    case content_flag
    when TC_NULL
      return :null, nil

    when TC_REFERENCE
      ref = @raw[@ptr..@ptr+3].unpack1 "N"
      ref -= 0x7e0000
      puts "Reference called #{ref}"
      @ptr += 4
      return :ref, ref

    when TC_PROXYCLASSDESC
      # newHandle
      handle = {type: :proxy_class_desc}
      handleid = reg_handle(handle)
      # proxyInterfaceName
      interface_ct = @raw[@ptr..@ptr+3].unpack1 'N'
      interface_names = []
      (0..interface_ct-1).each do |ith_interface|
        interface_names.push read_text
      end
      @handles[handleid][:proxy_interfaces] = interface_names
      
      # classAnnotation
      @handles[handleid][:annotations] = read_annotation
      
      # superClassDesc
      puts "superClassDesc"
      type, superclassdesc = read_content([TC_CLASSDESC, TC_NULL, TC_REFERENCE])
      puts "superClassDesc of type #{type} read at #{@ptr}"
      superclassdesc = @handles[superclassdesc] if type == :ref
      data = {name: class_name, flag: class_desc_flag, fields: fields_structure, annotations: annotations, superclass: superclassdesc}
      @handles[handleid] = data
      puts "EO superClassDesc of #{class_name} as well as newClassDesc dec at #{debug_anchor}"


    when TC_CLASSDESC
      # className
      debug_anchor = @ptr
      class_name = read_text
      puts "newClassDesc of class #{class_name}"
      # serialVersionUID
      ser_ver_uid = @raw[@ptr..@ptr+7].unpack1 "q"
      puts "#{@ptr}: ser_ver_uid #{"%x"%ser_ver_uid}"
      @ptr += 8
      # newHandle
      handle = {type: :class_desc, name: class_name}
      handleid = reg_handle(handle)
      
      # classDescInfo-classDesInfoFlags
      class_desc_flag = @raw[@ptr].unpack1 "C"
      puts "#{@ptr}: class_desc_flag 0x#{"%02x"%class_desc_flag}"
      @ptr += 1
      
      # classDescInfo-fields
      fields_structure = read_field_spec
      # classDescInfo-classAnnotation: expect an end
      puts "Start classDescInfo-classAnnotation of #{class_name}"
      annotations = read_annotation
      puts "End of classDescInfo-classAnnotation of #{class_name}"

      # superClassDesc
      puts "superClassDesc"
      type, superclassdesc = read_content([TC_CLASSDESC, TC_NULL, TC_REFERENCE])
      puts "superClassDesc of type #{type} read at #{@ptr}"
      superclassdesc = @handles[superclassdesc] if type == :ref
      data = {name: class_name, flag: class_desc_flag, fields: fields_structure, annotations: annotations, superclass: superclassdesc}
      @handles[handleid] = data
      puts "EO superClassDesc of #{class_name} as well as newClassDesc dec at #{debug_anchor}"
      return :class_desc, data

    when TC_OBJECT
      debug_anchor = @ptr-1
      puts "new object"
      values = []
      object = {}
      
      # classDesc
      type, class_spec = read_content([TC_CLASSDESC, TC_REFERENCE])
      case type
      when :class_desc
        puts "New classDesc received by newObject declared at #{debug_anchor}"
      when :ref
        puts "Referring to class_desc in @handles[#{class_spec}] for newObject at #{debug_anchor}"
        class_spec = @handles[class_spec]
      end
      
      # newHandle
      object[:class] = class_spec
      ref = reg_handle(object)
      
      # classData
      # Travel through classes from the oldest ancestor
      begin
      classes = list_ancestral_line(class_spec)
      rescue
        puts "problematic ancestral line class"
        puts class_spec
        binding.pry
      end
      puts "Beginning to deal with classData at #{@ptr}, classDescFlag #{class_spec[:flag]} with classes #{classes}"
      
      classes.each do |klass|
        next unless klass[:fields]
        if (klass[:flag] & 0x02)>0 && !(0x01 & klass[:flag]>0)
          # no write class
          puts "no write class"
          puts klass[:fields]
          values = read_values(klass[:fields])
        elsif (klass[:flag] & 0x02 >0) && (0x01 & klass[:flag]>0)
          puts "write class"
          # write class
          values = read_values(klass[:fields])
          # objectAnnotation
          type = nil
          puts "Starts reading objectAnnotation for #{klass} at #{@ptr}"
          data = read_annotation
          puts "EO objectAnnotation at #{@ptr}"
        elsif (klass[:flag] & 0x04 >0) && !(klass[:flag] & 0x08>0)
          # External contents
          puts "externalContent"
          binding.pry
        elsif (klass[:flag] & 0x04>0) && (klass[:flag] & 0x08>0)
          # objectAnnotation
          type = nil
          puts "Starts reading objectAnnotation for #{klass} at #{@ptr}"
          data = read_annotation
          puts "EO objectAnnotation at #{@ptr}"
        else
          puts "questionable flag"
          binding.pry
        end
      end
      puts "End of classdata for object declared at #{debug_anchor}"

      @handles[ref][:values] = values
      return :object, values

    when TC_STRING
      str_length = @raw[@ptr..@ptr+1].unpack1 "n";
      raise "cannot get string length at #{@ptr}" unless str_length.is_a? Integer
      @ptr += 2
      str = @raw[@ptr..@ptr+str_length-1]
      @ptr += str_length
      string_obj = {type: 'String', content: str}
      reg_handle string_obj
      return :string, str

    when TC_LONGSTRING
      string_obj = {type: 'String'}
      reg_handle string_obj
      str_length = @raw[ptr].unpack1 "Q"; @ptr += 8 # Check the Endian-ness of this. Probably wrong.
      str = @raw[ptr..ptr+str_length-1]
      @handle.last[:content] = str
      @ptr += str_length
      return :string, str

    when TC_ARRAY
      puts "Array at #{@ptr-1}"
      type, class_spec = read_content([TC_CLASSDESC, TC_REFERENCE])
      if type == :class_spec
        reg_handle(class_spec) 
      elsif type == :ref
        puts "Referencing class spec # #{class_spec}"
        class_spec = @handles[class_spec]
        puts "Referenced: #{class_spec}"
      end
      arr_size, arr_items = @raw[@ptr..@ptr+7].unpack "nn"; @ptr += 4
      puts [arr_size, arr_items]
      arr_size = 4 if arr_size == 0 && class_spec[:name] =~ /\[F/ 
      data = Array.new(arr_items)
      (0..arr_items-1).each do |i|
        data[i] = @raw[@ptr+i*arr_size..@ptr+(i+1)*arr_size-1]
      end
      @ptr += arr_size*arr_items
      return :array, data

    when TC_CLASS
      if @raw[@ptr] == TC_NULL|| TC_REFERENCE || TC_PROXYCLASSDESC
        class_result = read_content

      else
        raise "classDesc is #{@raw[@ptr]} invald at #{@ptr}"
      end
      reg_handle(class_spec)
      return :class, nil
    
    when TC_BLOCKDATA
      length = @raw[@ptr].unpack1 "C"; @ptr += 1
      puts "Reading blockdata of length #{length}"
      data = @raw[@ptr..@ptr+length-1]
      @ptr += length
      return :blockdata, data
    when TC_BLOCKDATALONG
      length = @raw[@ptr].unpack1 "N"; @ptr += 4
      data = @raw[@ptr..@ptr+length-1]
      @ptr += length
      return :blockdata, data

    when TC_ENDBLOCKDATA
      return :block_end, nil

    when TC_RESET
      puts "Reset encountered at #{@ptr-1}. Dunno what to do with this."
    when TC_EXCEPTION
      puts "Exception encountered at #{@ptr-1}."
      
    when TC_ENUM
      puts "Watchout, ENUM at #{@ptr-1}"
      # classDesc
      type, class_spec = read_content([TC_CLASSDESC, TC_REFERENCE])
      raise "not yet ready for reference classDesc in ENUM" if type == :ref
      regnum = reg_handle(class_spec)
      enumconstantName = read_content(TC_STRING)
      @handles[regnum][:content] = enumconstantName

      when "\xff".b
        puts "FF at #{@ptr}"
    
    else
      raise "Weird type flag!!"
    end
  end
  
  def list_ancestral_line(class_spec)
    if class_spec[:superclass]
      return list_ancestral_line(class_spec[:superclass]) + [class_spec]
    else
      return [class_spec]
    end
  end
  def flatten_inherited_fields(class_spec)
    if class_spec[:superclass]
      return flatten_inherited_fields(class_spec[:superclass]) +class_spec[:fields]
    else
      return class_spec[:fields]
    end
  end

  def reg_handle(entity)
    @handles.push entity
    puts "Handle #{@handles.size-1} for #{entity}"
    return @handles.size-1
  end

  # classAnnotation and objectAnnotation can share the same method
  def read_annotation
      annotations = []
      while true do
        puts "Reading annotation at #{@ptr}"
        type, annotation = read_content
        puts "read annotation ending at #{@ptr}"
        if type == :block_end
          puts "block end reached for annotation at #{@ptr-1}"
          break
        end
        annotations.push annotation
      end
      annotations
  end
  
  # Read value/classdata
  def read_values(specs)
    values = []
    specs.each do |field|
      puts "Reading classdata value expecting #{field} at #{@ptr}"
      case field[1]
      when 'I'
        values.push @raw[@ptr..@ptr+3].unpack1 'N'
        @ptr += 4
      when 'F'
        values.push @raw[@ptr..@ptr+3].unpack1 'g' 
        @ptr += 4
      when /^L/
        type, data = read_content([TC_REFERENCE, TC_OBJECT, TC_STRING, TC_BLOCKDATA, TC_NULL])
        if type == :object
        elsif type == :ref
          puts "Got ref to prevObject at @handles[#{data}]"
        elsif type == :class_desc
        elsif type == :string
        elsif type == :null
        else
          raise "unknown object field type #{type} at #{@ptr}"
        end
        values.push data
      when 't'
        data = read_text
        values.push data
      when 'Z'
        # Boolean
        data = @raw[@ptr].unpack 'C'
        @ptr += 1
        values.push data
      when nil
        # Do nothing
      when 'D'
        # Double precision float
        data = @raw[@ptr..@ptr+7].unpack1 'G'
        @ptr += 8
        values.push data
      when /^\[/
        puts "Array..."
        read_content(TC_ARRAY)
      else
        raise "unknown field type #{field[1]} at #{@ptr}"
      end
    end
    values
  end
  
  def read_field_spec
    fieldn = @raw[@ptr..@ptr+1].unpack1 'n'
    puts "Reading fields at #{@ptr}, expecting #{fieldn} fields"
    @ptr += 2
    fields = Array.new(fieldn)
    (0..fieldn-1).each do |i|
      field_type = @raw[@ptr]
      @ptr += 1
      case field_type
      # Byte, Char, Double, Float, Integer, Long, Short, Bool
      when 'B'.b, 'C'.b, 'D'.b, 'F'.b, 'I'.b, 'J'.b, 'S'.b, 'Z'.b
        field_name = read_text
      when "L".b # Object
        field_name = read_text
        classname1_type, classname1 = read_content([TC_STRING, TC_REFERENCE])
        if classname1_type == :ref
          classname1 = @handles[classname1][:content]
        end
        # Watchout: overwriting field_type from general 'L'
        field_type = classname1
      when "[".b # Array
        field_name = read_text
        string_type, classname1 = read_content([TC_STRING, TC_REFERENCE])
        field_type = classname1
        if classname1_type == :ref
          classname1 = @handles[classname1][:content]
        end
      else
        raise "Field type 0x#{field_type.unpack1("H*")} not recognized at #{@ptr-1}"
      end
      puts "Field type #{field_type} called #{field_name}"
      fields[i] = [field_name, field_type]
    end
    return fields
  end
  def read_text
    length = @raw[@ptr..@ptr+1].unpack1 "n"
    puts "Reading text of length #{length} at #{@ptr}"
    @ptr += 2
    text = @raw[@ptr..@ptr+length-1]
    @ptr += length
    return text
  end

end

raw = File.open("./weird.qpdata","rb"){|f| f.read}
#raw = File.open("./test_class_stream.stream","rb"){|f| f.read}
javastream1 = JavaObjectStream.new raw
