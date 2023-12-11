import logging
import struct

"""
struct DexHeader {
    u1  magic[8]         // 魔数
    u4  checksum         // adler 校验值
    u1  signature[kSHA1DigestLen] // sha1 校验值
    u4  fileSize         // DEX 文件大小
    u4  headerSize       // DEX 文件头大小
    u4  endianTag        // 字节序
    u4  linkSize         // 链接段大小
    u4  linkOff          // 链接段的偏移量
    u4  mapOff           // DexMapList 偏移量
    u4  stringIdsSize    // DexStringId 个数
    u4  stringIdsOff     // DexStringId 偏移量
    u4  typeIdsSize      // DexTypeId 个数
    u4  typeIdsOff       // DexTypeId 偏移量
    u4  protoIdsSize     // DexProtoId 个数
    u4  protoIdsOff      // DexProtoId 偏移量
    u4  fieldIdsSize     // DexFieldId 个数
    u4  fieldIdsOff      // DexFieldId 偏移量
    u4  methodIdsSize    // DexMethodId 个数
    u4  methodIdsOff     // DexMethodId 偏移量
    u4  classDefsSize    // DexCLassDef 个数
    u4  classDefsOff     // DexClassDef 偏移量
    u4  dataSize         // 数据段大小
    u4  dataOff          // 数据段偏移量
}
"""
class DexHeader:
    def __init__(self, file) -> None:
        # dont consider efficiency
        self.file = file
        
        self.magic = self.readBytes(0, 8)
        self.checksum = self.readUInt32(0x8)
        self.signature = self.readBytes(0xC, 0x14)
        self.fileSize = self.readUInt32(0x20)
        self.headerSize = self.readUInt32(0x24)
        self.endianTag = self.readBytes(0x28, 4)  
        self.linkSize = self.readUInt32(0x2C)
        self.linkOff = self.readUInt32(0x30)
        self.mapOff = self.readUInt32(0x34)
        self.stringIdsSize = self.readUInt32(0x38)
        self.stringIdsOff = self.readUInt32(0x3C)
        self.typeIdsSize = self.readUInt32(0x40)
        self.typeIdsOff = self.readUInt32(0x44)
        self.protoIdsSize = self.readUInt32(0x48)
        self.protoIdsOff = self.readUInt32(0x4C)
        self.fieldIdsSize = self.readUInt32(0x50)
        self.fieldIdsOff = self.readUInt32(0x54)
        self.methodIdsSize = self.readUInt32(0x58)
        self.methodIdsOff = self.readUInt32(0x5C)
        self.classDefsSize = self.readUInt32(0x60)
        self.classDefsOff = self.readUInt32(0x64)
        self.dataSize = self.readUInt32(0x68)
        self.dataOff = self.readUInt32(0x6C)
    
    def readBytes(self, offset, len):
        # 不做检查，报错了好查问题
        return self.file[offset:offset+len]
    
    def readUInt32(self, offset):
        return struct.unpack("<I", self.file[offset:offset+4])[0]
    
    def pp(self):
        print("magic:\t{}".format(self.magic))
        print("checksum:\t0x{:x}".format(self.checksum))
        print("signature:\t{}".format(self.signature))
        print("fileSize:\t0x{:x}".format(self.fileSize))
        print("headerSize:\t0x{:x}".format(self.headerSize))
        print("endianTag:\t{}".format(self.endianTag))
        print("linkSiz:\t0x{:x}".format(self.linkSize))
        print("linkOff:\t0x{:x}".format(self.linkOff))
        print("mapOff:\t\t0x{:x}".format(self.mapOff))
        print("stringIdsSize:\t0x{:x}".format(self.stringIdsSize))
        print("stringIdsOff:\t0x{:x}".format(self.stringIdsOff))
        print("typeIdsSize:\t0x{:x}".format(self.typeIdsSize))
        print("typeIdsOff:\t0x{:x}".format(self.typeIdsOff))
        print("protoIdsSize:\t0x{:x}".format(self.protoIdsSize))
        print("protoIdsOff:\t0x{:x}".format(self.protoIdsOff))
        print("fieldIdsSize:\t0x{:x}".format(self.fieldIdsSize))
        print("fieldIdsOff:\t0x{:x}".format(self.fieldIdsOff))
        print("methodIdsSize:\t0x{:x}".format(self.methodIdsSize))
        print("methodIdsOff:\t0x{:x}".format(self.methodIdsOff))
        print("classDefsSize:\t0x{:x}".format(self.classDefsSize))
        print("classDefsOff:\t0x{:x}".format(self.classDefsOff))
        print("dataSize:\t0x{:x}".format(self.dataSize))
        print("dataOff:\t0x{:x}".format(self.dataOff))
    

"""
struct DexStringId {
    u4 stringDataOff;
};
"""    
class DexStringId:
    def __init__(self) -> None:
        # self.stringIdsSize = None
        # self.stringIdsOff = None
        self.stringIdsList = []
        self.stringsList = []
        
    def pp(self):
        print("parse Strings")
        assert len(self.stringIdsList) == len(self.stringsList)
        for i in range(len(self.stringIdsList)):
            print(f"str[{i}]:\t\t{self.stringsList[i]}")
        
class DexTypeId:
    def __init__(self) -> None:
        self.typeIdsList = []
        self.typeList = []
    
    def pp(self):
        print("parse Type")
        assert len(self.typeIdsList) == len(self.typeList)
        for i in range(len(self.typeIdsList)):
            print(f"type[{i}]:\t\t{self.typeList[i]}")

"""
struct DexProtoId {
    u4  shortyIdx;          /* index into stringIds for shorty descriptor */
    u4  returnTypeIdx;      /* index into typeIds list for return type */
    u4  parametersOff;      /* file offset to type_list for parameter types */
};
"""
class DexProtoId:
    def __init__(self) -> None:
        """
        shortyIdx -> str[i]
        returnTypeIdx -> type[i]
        parameters_off -> UInt32
        """
        self.proto_id_items = []
        
    def pp(self):
        print("parse Proto")
        print(self.proto_id_items)

"""
struct DexFieldId {
    u2  classIdx;           /* index into typeIds list for defining class */
    u2  typeIdx;            /* index into typeIds for field type */
    u4  nameIdx;            /* index into stringIds for field name */
};
"""
class DexFieldId:
    def __init__(self) -> None:
        self.field_id_items = []
    
    def pp(self):
        print("parse Field")
        print(self.field_id_items)

"""
struct DexMethodId {
    u2  classIdx;           /* index into typeIds list for defining class */
    u2  protoIdx;           /* index into protoIds for method prototype */
    u4  nameIdx;            /* index into stringIds for method name */
};
"""
class DexMethodId:
    def __init__(self) -> None:
        self.method_id_items = []
    
    def pp(self):
        print("parse Method")
        print(self.method_id_items)
        
"""
struct DexClassDef {
    u4  classIdx;           /* index into typeIds for this class */
    u4  accessFlags;
    u4  superclassIdx;      /* index into typeIds for superclass */
    u4  interfacesOff;      /* file offset to DexTypeList */
    u4  sourceFileIdx;      /* index into stringIds for source file name */
    u4  annotationsOff;     /* file offset to annotations_directory_item */
    u4  classDataOff;       /* file offset to class_data_item */
    u4  staticValuesOff;    /* file offset to DexEncodedArray */
};
""" 
class DexClassDef:
    def __init__(self) -> None:
        self.class_def_items = []
        self.class_datas = []
    
    def pp(self):
        print("parse Class")
        print(self.class_def_items)

"""
struct DexClassData {
    DexClassDataHeader header;
    DexField*          staticFields;
    DexField*          instanceFields;
    DexMethod*         directMethods;
    DexMethod*         virtualMethods;
};
struct DexClassDataHeader {
    u4 staticFieldsSize;
    u4 instanceFieldsSize;
    u4 directMethodsSize;
    u4 virtualMethodsSize;
};
struct DexField {
    u4 fieldIdx;    /* index to a field_id_item */
    u4 accessFlags;
};
struct DexMethod {
    u4 methodIdx;    /* index to a method_id_item */
    u4 accessFlags;
    u4 codeOff;      /* file offset to a code_item */
};
"""
class DexClassDataHeader:
    def __init__(self) -> None:
        self.staticFieldsSize = None
        self.instanceFieldsSize = None
        self.directMethodsSize = None
        self.virtualMethodsSize = None
        
    def pp(self):
        print(self.staticFieldsSize)
        print(self.instanceFieldsSize)
        print(self.directMethodsSize )
        print(self.virtualMethodsSize)
        
class DexField:
    def __init__(self) -> None:
        self.fieldIdx = None
        self.accessFlags = None
        
    def pp(self):
        print(self.fieldIdx)
        print(self.accessFlags)

class DexMethod:
    def __init__(self) -> None:
        self.methodIdx = None
        self.accessFlags = None
        self.codeOff = None
        self.code = None
        
    def pp(self):
        print(self.methodIdx)
        print(self.accessFlags)
        print(self.codeOff)
   
"""
struct DexCode {
    u2  registersSize;  // 寄存器个数
    u2  insSize;        // 参数的个数
    u2  outsSize;       // 调用其他方法时使用的寄存器个数
    u2  triesSize;      // try/catch 语句个数
    u4  debugInfoOff;   // debug 信息的偏移量
    u4  insnsSize;      // 指令集的个数
    u2  insns[1];       // 指令集
    /* followed by optional u2 padding */  // 2 字节，用于对齐
    /* followed by try_item[triesSize] */
    /* followed by uleb128 handlersSize */
    /* followed by catch_handler_item[handlersSize] */
};
"""     
class DexCode:
    def __init__(self) -> None:
        self.registersSize = None
        self.insSize = None
        self.outsSize = None  
        self.triesSize = None 
        self.debugInfoOff = None
        self.insnsSize = None
        # self.insns[1];       
    
      
class DexClassData:
    def __init__(self) -> None:
        self.header = DexClassDataHeader()
        self.staticFields = []
        self.instanceFields = []
        self.directMethods = []
        self.virtualMethods = []
    
    # def pp(self):
    #     print(self.)

class DexReader:
    def __init__(self, path:str):
        self.path = path
        
        try:
            with open(self.path, "rb") as tmp:
                self.file = tmp.read()
            logging.info("[*] dex file read")
        except:
            logging.error("[!] error while reading dex.")
        ## header
        self.dexHeader = DexHeader(self.file)
        # self.dexHeader.pp()
        
        ## string_id
        self.dexStringId = DexStringId()
        # self.dexStringId.stringIdsOff = self.dexHeader.stringIdsOff
        # self.dexStringId.stringIdsSize = self.dexHeader.stringIdsSize
        self.dexStringId.stringIdsList.clear()
        self.dexStringId.stringsList.clear()
        for i in range(self.dexHeader.stringIdsSize):
            tmpId = self.readUInt32(self.dexHeader.stringIdsOff + 4*i)
            self.dexStringId.stringIdsList.append(tmp)
            tmpStr = self.readString(tmpId)
            self.dexStringId.stringsList.append(tmpStr)
        # self.dexStringId.pp()
            
        ## type_id
        self.dexTypeId = DexTypeId()
        self.dexTypeId.typeIdsList.clear()
        self.dexTypeId.typeList.clear()
        for i in range(self.dexHeader.typeIdsSize):
            tmpId = self.readUInt32(self.dexHeader.typeIdsOff + 4*i)
            self.dexTypeId.typeIdsList.append(tmp)
            tmpStr = self.dexStringId.stringsList[tmpId]
            self.dexTypeId.typeList.append(tmpStr)
        # self.dexTypeId.pp()
        
        # proto_id
        self.dexProtoId = DexProtoId()
        for i in range(self.dexHeader.protoIdsSize):
            tmp = {
                'shortyIdx' : self.readUInt32(
                    self.dexHeader.protoIdsOff + 4*3*i
                ),
                'returnTypeIdx' : self.readUInt32(
                    self.dexHeader.protoIdsOff + 4*3*i + 4
                ),
                'parametersOff' : self.readUInt32(
                    self.dexHeader.protoIdsOff + 4*3*i + 8
                )
            }
            tmp['shorty'] = self.dexStringId.stringsList[tmp['shortyIdx']]
            tmp['returnType'] = self.dexTypeId.typeList[tmp['returnTypeIdx']]
            self.dexProtoId.proto_id_items.append(tmp)
        # self.dexProtoId.pp()
        
        # field_id
        self.dexFieldId = DexFieldId()
        for i in range(self.dexHeader.fieldIdsSize):
            tmp = {
                'classIdx' : self.readUShort(self.dexHeader.fieldIdsOff + 8*i),
                'typeIdx' : self.readUShort(self.dexHeader.fieldIdsOff + 8*i + 2),
                'nameIdx' : self.readUInt32(self.dexHeader.fieldIdsOff + 8*i + 4),
            }
            tmp['class'] = self.dexTypeId.typeList[tmp['classIdx']]
            tmp['type'] = self.dexTypeId.typeList[tmp['typeIdx']]
            tmp['name'] = self.dexStringId.stringsList[tmp['nameIdx']]
            self.dexFieldId.field_id_items.append(tmp)
        # self.dexFieldId.pp()
        
        # method_id
        self.dexMethodId = DexMethodId()
        for i in range(self.dexHeader.methodIdsSize):
            tmp = {
                'classIdx'  : self.readUShort(self.dexHeader.methodIdsOff + 8*i + 0),
                'protoIdx'  : self.readUShort(self.dexHeader.methodIdsOff + 8*i + 2),
                'nameIdx'  : self.readUInt32(self.dexHeader.methodIdsOff + 8*i + 4),
            }
            tmp['class'] = self.dexTypeId.typeList[tmp['classIdx']]
            tmp['proto'] = self.dexProtoId.proto_id_items[tmp['protoIdx']]
            tmp['name'] = self.dexStringId.stringsList[tmp['nameIdx']]
            self.dexMethodId.method_id_items.append(tmp)
        # self.dexMethodId.pp()
        
        # class_def
        self.dexClassDef = DexClassDef()
        for i in range(self.dexHeader.classDefsSize):
            tmp = {
                'classIdx'  : self.readUInt32(self.dexHeader.classDefsOff + 0x20*i),
                'accessFlags'  : self.readUInt32(self.dexHeader.classDefsOff + 0x20*i + 4),
                'superclassIdx'  : self.readUInt32(self.dexHeader.classDefsOff + 0x20*i + 4*2),
                'interfacesOff'  : self.readUInt32(self.dexHeader.classDefsOff + 0x20*i + 4*3),
                'sourceFileIdx'  : self.readUInt32(self.dexHeader.classDefsOff + 0x20*i + 4*4),
                'annotationsOff'  : self.readUInt32(self.dexHeader.classDefsOff + 0x20*i + 4*5),
                'classDataOff'  : self.readUInt32(self.dexHeader.classDefsOff + 0x20*i + 4*6),
                'staticValuesOff'  : self.readUInt32(self.dexHeader.classDefsOff + 0x20*i + 4*7)
            }
            tmp['class'] = self.dexTypeId.typeList[tmp['classIdx']]
            tmp['superclass'] = self.dexTypeId.typeList[tmp['superclassIdx']]
            # print(tmp['sourceFileIdx'])
            try:
                tmp['sourceFile'] = self.dexStringId.stringsList[tmp['sourceFileIdx']]
            except:
                tmp['sourceFile'] = b'RH_NOT_AVAILABLE'
            # print(tmp['sourceFile'])
            self.dexClassDef.class_def_items.append(tmp)
            
            classDataOff = tmp['classDataOff']
            classData = DexClassData()
            classData.header.staticFieldsSize, newOff = self.readULEB128(classDataOff)
            classData.header.instanceFieldsSize, newOff = self.readULEB128(newOff)
            classData.header.directMethodsSize, newOff = self.readULEB128(newOff)
            classData.header.virtualMethodsSize, newOff = self.readULEB128(newOff)
            # classData.header.pp()
            for i in range(classData.header.staticFieldsSize):
                tmp = DexField()
                tmp.fieldIdx, newOff = self.readULEB128(newOff)
                print(newOff)
                tmp.accessFlags, newOff = self.readULEB128(newOff)
                classData.staticFields.append(tmp)
            for i in range(classData.header.instanceFieldsSize):
                tmp = DexField()
                tmp.fieldIdx, newOff = self.readULEB128(newOff)
                tmp.accessFlags, newOff = self.readULEB128(newOff)
                classData.instanceFields.append(tmp)
            for i in range(classData.header.directMethodsSize):
                tmp = DexMethod()
                tmp.methodIdx, newOff = self.readULEB128(newOff)
                tmp.accessFlags, newOff = self.readULEB128(newOff)
                tmp.codeOff, newOff = self.readULEB128(newOff)
                # tmp.code = self.readBytes
                # !TODO code structure
                classData.directMethods.append(tmp)
                
            for i in range(classData.header.virtualMethodsSize):
                tmp = DexMethod()
                tmp.methodIdx, newOff = self.readULEB128(newOff)
                tmp.accessFlags, newOff = self.readULEB128(newOff)
                tmp.codeOff, newOff = self.readULEB128(newOff)
                # tmp.code = self.readBytes
                # !TODO code structure
                classData.virtualMethods.append(tmp)
            self.dexClassDef.class_datas.append(classData)
        
    def readULEB128(self, offset):
        result = 0
        count = 0
        while True:
            cur = self.file[offset]
            cur &= 0xFF
            result |= (cur & 0x7F) << count * 7
            count += 1
            offset += 1
            if (cur & 0x80) == 128 and count < 5:
                pass
            else:
                break
        return result, offset

        
    def readBytes(self, offset, len):
        # 不做检查，报错了好查问题
        return self.file[offset:offset+len]
    
    def readUInt32(self, offset):
        return struct.unpack("<I", self.file[offset:offset+4])[0]

    def readUShort(self, offset):
        return struct.unpack("<I", self.file[offset:offset+2].ljust(4, b'\x00'))[0]

    def readString(self, offset, encoding="utf-8") -> bytes:
        idx = offset
        len = self.readBytes(idx, 1)[0]
        idx += 1
        tmpStr = self.readBytes(idx, len+1)
        # return tmpStr
        # print(tmpStr)
        return tmpStr
            
if __name__ == "__main__":
    path = "D:/Android/Dex/classes_dec.dex"
    dexReader = DexReader(path)