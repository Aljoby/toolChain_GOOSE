import struct 

class DecoderError(Exception):
    pass

def unpack_varint(data, length):
    """ Decodes a variable length integer """
    if length == 1: 
        data = struct.unpack('!h', '\x00' + data)[0]
    elif length == 2:
        data = struct.unpack('!h', data)[0]
    elif length == 4:
        data = struct.unpack('!i', data)[0]
    else:
        data = -1
    return data

def encoder(data, tagmap):
    keys = tagmap.keys()
    keys.sort()
    packed_data = ''

    for key in keys:
        try:
            attr = data[tagmap[key][0]]
        except KeyError:
            continue

        tag = key[0] + key[1] + key[2]
        tag = struct.pack('!B', tag)
        package = attr.pack()
        if len(package) < 128:
            length = struct.pack('!B', len(package))
        else:  # HACK.. this will only support lengths up to 254.
            length = struct.pack('!BB', 129, len(package))
        packed_data += tag + length + package
        #print repr(tag + length + package)

    return packed_data

def decoder(data, tagmap, ignore_errors=True, decode_as_list=False):
    """ Decodes binary data encoded in a BER format and return a dictonary.

    Keyword Arguments:
    data -- the binary data to decode stored in a string
    tagmap -- a dictionary keyed by a tag tuple (class, format, id) as integer
              values with tuple values (name, type).
    ignore_errors -- will cause the decoder to skip past errors and continue

    """
    if decode_as_list:
        results = list()
    else:
        results = dict() #dictionary data type, convert x = 5 to {'x': 5 }

    #print(data)
    print('\n')
    while len(data) > 0:
        #print("data length is %d" % (len(data)))
        chunk = 1
        tag = ord(data[:chunk]) #tag value is decimal, for example 128 is 80, and 128 is 81
        #print(hex(tag))
        #print(data[:chunk])
        #print("tag: ")
        #print(tag)
        data = data[chunk:] 
        #print("data: ")
        #print(data)
        tag_class = tag & 0xC0 # is and between the hex represntation of tag and c0, for example 80 and C0 = 128, 81 and C0 = 128
        #print("tag_class: ")
        #print(tag_class)
        tag_format = tag & 0x20
        #print("tag_format: ")
        #print(tag_format)
        tag_id = tag & 0x1F
        #print("tag_id: ")
        #print(tag_id)

        length = ord(data[:chunk]) # the second byte in pcap
        #print("length: ")
        #print(length)
        data = data[chunk:]
        if length & 0x80 == 0x80: # length field is longer than a byte # This might be for allData field, becouse the length might be two bytes
            n = length & 0x7F 
            #print("n: ")
            #print(n)
            length = unpack_varint(data[:n], n)
            #print("length unpack_variant: ")
            #print(length)
            data = data[n:] 
            #print("data: ")
            #print(data)
        try:
            name = tagmap[(tag_class, tag_format, tag_id)][0]
            #print("name: ")
            #print(name)
            inst = tagmap[(tag_class, tag_format, tag_id)][1]
            #print("inst: ")
            #print(inst)
            val = inst(data[:length], length) # exception handling? # this looks calling the class data type
            #print("val: ")
            #print(val)
            val.tag = (tag_class, tag_format, tag_id)
            #print("val.tag: ")
            #print(val.tag)
            #print('\n')
        except KeyError:
            if ignore_errors:
                print 'Unfound tag %s,%s,%s' % (tag_class, tag_format, tag_id)
                continue
            else:
                raise DecoderError("Tag not found in tagmap")
        finally:
            data = data[length:] 
   
        if decode_as_list:
            results.append(val)
        else:
            results[name] = val

    return results
