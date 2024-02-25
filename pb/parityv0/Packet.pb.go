// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        v4.25.2
// source: parity/v0/Packet.proto

package parityv0

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type IndexPacket struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	InputFile   *InputFile   `protobuf:"bytes,1,opt,name=input_file,json=inputFile,proto3" json:"input_file,omitempty"`
	ShardConfig *ShardConfig `protobuf:"bytes,2,opt,name=shard_config,json=shardConfig,proto3" json:"shard_config,omitempty"`
	BlockSet    *BlockSet    `protobuf:"bytes,3,opt,name=block_set,json=blockSet,proto3" json:"block_set,omitempty"`
}

func (x *IndexPacket) Reset() {
	*x = IndexPacket{}
	if protoimpl.UnsafeEnabled {
		mi := &file_parity_v0_Packet_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IndexPacket) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IndexPacket) ProtoMessage() {}

func (x *IndexPacket) ProtoReflect() protoreflect.Message {
	mi := &file_parity_v0_Packet_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IndexPacket.ProtoReflect.Descriptor instead.
func (*IndexPacket) Descriptor() ([]byte, []int) {
	return file_parity_v0_Packet_proto_rawDescGZIP(), []int{0}
}

func (x *IndexPacket) GetInputFile() *InputFile {
	if x != nil {
		return x.InputFile
	}
	return nil
}

func (x *IndexPacket) GetShardConfig() *ShardConfig {
	if x != nil {
		return x.ShardConfig
	}
	return nil
}

func (x *IndexPacket) GetBlockSet() *BlockSet {
	if x != nil {
		return x.BlockSet
	}
	return nil
}

type InputFile struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hash string `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	Size uint64 `protobuf:"varint,2,opt,name=size,proto3" json:"size,omitempty"`
}

func (x *InputFile) Reset() {
	*x = InputFile{}
	if protoimpl.UnsafeEnabled {
		mi := &file_parity_v0_Packet_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InputFile) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InputFile) ProtoMessage() {}

func (x *InputFile) ProtoReflect() protoreflect.Message {
	mi := &file_parity_v0_Packet_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InputFile.ProtoReflect.Descriptor instead.
func (*InputFile) Descriptor() ([]byte, []int) {
	return file_parity_v0_Packet_proto_rawDescGZIP(), []int{1}
}

func (x *InputFile) GetHash() string {
	if x != nil {
		return x.Hash
	}
	return ""
}

func (x *InputFile) GetSize() uint64 {
	if x != nil {
		return x.Size
	}
	return 0
}

type ShardConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BlockSize        uint64            `protobuf:"varint,1,opt,name=block_size,json=blockSize,proto3" json:"block_size,omitempty"`
	Count            uint64            `protobuf:"varint,2,opt,name=count,proto3" json:"count,omitempty"`
	RecoveryCount    uint64            `protobuf:"varint,3,opt,name=recovery_count,json=recoveryCount,proto3" json:"recovery_count,omitempty"`
	CodeMatrixConfig *CodeMatrixConfig `protobuf:"bytes,4,opt,name=code_matrix_config,json=codeMatrixConfig,proto3" json:"code_matrix_config,omitempty"`
}

func (x *ShardConfig) Reset() {
	*x = ShardConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_parity_v0_Packet_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ShardConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ShardConfig) ProtoMessage() {}

func (x *ShardConfig) ProtoReflect() protoreflect.Message {
	mi := &file_parity_v0_Packet_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ShardConfig.ProtoReflect.Descriptor instead.
func (*ShardConfig) Descriptor() ([]byte, []int) {
	return file_parity_v0_Packet_proto_rawDescGZIP(), []int{2}
}

func (x *ShardConfig) GetBlockSize() uint64 {
	if x != nil {
		return x.BlockSize
	}
	return 0
}

func (x *ShardConfig) GetCount() uint64 {
	if x != nil {
		return x.Count
	}
	return 0
}

func (x *ShardConfig) GetRecoveryCount() uint64 {
	if x != nil {
		return x.RecoveryCount
	}
	return 0
}

func (x *ShardConfig) GetCodeMatrixConfig() *CodeMatrixConfig {
	if x != nil {
		return x.CodeMatrixConfig
	}
	return nil
}

type CodeMatrixConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CodeMatrixKind string `protobuf:"bytes,1,opt,name=code_matrix_kind,json=codeMatrixKind,proto3" json:"code_matrix_kind,omitempty"`
}

func (x *CodeMatrixConfig) Reset() {
	*x = CodeMatrixConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_parity_v0_Packet_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CodeMatrixConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CodeMatrixConfig) ProtoMessage() {}

func (x *CodeMatrixConfig) ProtoReflect() protoreflect.Message {
	mi := &file_parity_v0_Packet_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CodeMatrixConfig.ProtoReflect.Descriptor instead.
func (*CodeMatrixConfig) Descriptor() ([]byte, []int) {
	return file_parity_v0_Packet_proto_rawDescGZIP(), []int{3}
}

func (x *CodeMatrixConfig) GetCodeMatrixKind() string {
	if x != nil {
		return x.CodeMatrixKind
	}
	return ""
}

type BlockSet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Input  []*Block `protobuf:"bytes,1,rep,name=input,proto3" json:"input,omitempty"`
	Parity []*Block `protobuf:"bytes,2,rep,name=parity,proto3" json:"parity,omitempty"`
}

func (x *BlockSet) Reset() {
	*x = BlockSet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_parity_v0_Packet_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BlockSet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BlockSet) ProtoMessage() {}

func (x *BlockSet) ProtoReflect() protoreflect.Message {
	mi := &file_parity_v0_Packet_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BlockSet.ProtoReflect.Descriptor instead.
func (*BlockSet) Descriptor() ([]byte, []int) {
	return file_parity_v0_Packet_proto_rawDescGZIP(), []int{4}
}

func (x *BlockSet) GetInput() []*Block {
	if x != nil {
		return x.Input
	}
	return nil
}

func (x *BlockSet) GetParity() []*Block {
	if x != nil {
		return x.Parity
	}
	return nil
}

type Block struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hash string `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
}

func (x *Block) Reset() {
	*x = Block{}
	if protoimpl.UnsafeEnabled {
		mi := &file_parity_v0_Packet_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Block) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Block) ProtoMessage() {}

func (x *Block) ProtoReflect() protoreflect.Message {
	mi := &file_parity_v0_Packet_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Block.ProtoReflect.Descriptor instead.
func (*Block) Descriptor() ([]byte, []int) {
	return file_parity_v0_Packet_proto_rawDescGZIP(), []int{5}
}

func (x *Block) GetHash() string {
	if x != nil {
		return x.Hash
	}
	return ""
}

var File_parity_v0_Packet_proto protoreflect.FileDescriptor

var file_parity_v0_Packet_proto_rawDesc = []byte{
	0x0a, 0x16, 0x70, 0x61, 0x72, 0x69, 0x74, 0x79, 0x2f, 0x76, 0x30, 0x2f, 0x50, 0x61, 0x63, 0x6b,
	0x65, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1c, 0x78, 0x6f, 0x72, 0x6b, 0x65, 0x76,
	0x69, 0x6e, 0x2e, 0x62, 0x69, 0x74, 0x63, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2e, 0x70, 0x61, 0x72,
	0x69, 0x74, 0x79, 0x2e, 0x76, 0x30, 0x22, 0xe8, 0x01, 0x0a, 0x0b, 0x49, 0x6e, 0x64, 0x65, 0x78,
	0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x12, 0x46, 0x0a, 0x0a, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f,
	0x66, 0x69, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x78, 0x6f, 0x72,
	0x6b, 0x65, 0x76, 0x69, 0x6e, 0x2e, 0x62, 0x69, 0x74, 0x63, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2e,
	0x70, 0x61, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x30, 0x2e, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x46,
	0x69, 0x6c, 0x65, 0x52, 0x09, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x4c,
	0x0a, 0x0c, 0x73, 0x68, 0x61, 0x72, 0x64, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x78, 0x6f, 0x72, 0x6b, 0x65, 0x76, 0x69, 0x6e, 0x2e,
	0x62, 0x69, 0x74, 0x63, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2e, 0x70, 0x61, 0x72, 0x69, 0x74, 0x79,
	0x2e, 0x76, 0x30, 0x2e, 0x53, 0x68, 0x61, 0x72, 0x64, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52,
	0x0b, 0x73, 0x68, 0x61, 0x72, 0x64, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x43, 0x0a, 0x09,
	0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x73, 0x65, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x26, 0x2e, 0x78, 0x6f, 0x72, 0x6b, 0x65, 0x76, 0x69, 0x6e, 0x2e, 0x62, 0x69, 0x74, 0x63, 0x65,
	0x6e, 0x73, 0x75, 0x73, 0x2e, 0x70, 0x61, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x30, 0x2e, 0x42,
	0x6c, 0x6f, 0x63, 0x6b, 0x53, 0x65, 0x74, 0x52, 0x08, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x53, 0x65,
	0x74, 0x22, 0x33, 0x0a, 0x09, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x12,
	0x0a, 0x04, 0x68, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x61,
	0x73, 0x68, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x04, 0x73, 0x69, 0x7a, 0x65, 0x22, 0xc7, 0x01, 0x0a, 0x0b, 0x53, 0x68, 0x61, 0x72, 0x64,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x1d, 0x0a, 0x0a, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f,
	0x73, 0x69, 0x7a, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x25, 0x0a, 0x0e, 0x72,
	0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x0d, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x43, 0x6f, 0x75,
	0x6e, 0x74, 0x12, 0x5c, 0x0a, 0x12, 0x63, 0x6f, 0x64, 0x65, 0x5f, 0x6d, 0x61, 0x74, 0x72, 0x69,
	0x78, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2e,
	0x2e, 0x78, 0x6f, 0x72, 0x6b, 0x65, 0x76, 0x69, 0x6e, 0x2e, 0x62, 0x69, 0x74, 0x63, 0x65, 0x6e,
	0x73, 0x75, 0x73, 0x2e, 0x70, 0x61, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x30, 0x2e, 0x43, 0x6f,
	0x64, 0x65, 0x4d, 0x61, 0x74, 0x72, 0x69, 0x78, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x10,
	0x63, 0x6f, 0x64, 0x65, 0x4d, 0x61, 0x74, 0x72, 0x69, 0x78, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x22, 0x3c, 0x0a, 0x10, 0x43, 0x6f, 0x64, 0x65, 0x4d, 0x61, 0x74, 0x72, 0x69, 0x78, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x12, 0x28, 0x0a, 0x10, 0x63, 0x6f, 0x64, 0x65, 0x5f, 0x6d, 0x61, 0x74,
	0x72, 0x69, 0x78, 0x5f, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e,
	0x63, 0x6f, 0x64, 0x65, 0x4d, 0x61, 0x74, 0x72, 0x69, 0x78, 0x4b, 0x69, 0x6e, 0x64, 0x22, 0x82,
	0x01, 0x0a, 0x08, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x53, 0x65, 0x74, 0x12, 0x39, 0x0a, 0x05, 0x69,
	0x6e, 0x70, 0x75, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x78, 0x6f, 0x72,
	0x6b, 0x65, 0x76, 0x69, 0x6e, 0x2e, 0x62, 0x69, 0x74, 0x63, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2e,
	0x70, 0x61, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x30, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x52,
	0x05, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x12, 0x3b, 0x0a, 0x06, 0x70, 0x61, 0x72, 0x69, 0x74, 0x79,
	0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x78, 0x6f, 0x72, 0x6b, 0x65, 0x76, 0x69,
	0x6e, 0x2e, 0x62, 0x69, 0x74, 0x63, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2e, 0x70, 0x61, 0x72, 0x69,
	0x74, 0x79, 0x2e, 0x76, 0x30, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x52, 0x06, 0x70, 0x61, 0x72,
	0x69, 0x74, 0x79, 0x22, 0x1b, 0x0a, 0x05, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x12, 0x12, 0x0a, 0x04,
	0x68, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68,
	0x42, 0x24, 0x5a, 0x22, 0x78, 0x6f, 0x72, 0x6b, 0x65, 0x76, 0x69, 0x6e, 0x2e, 0x64, 0x65, 0x76,
	0x2f, 0x62, 0x69, 0x74, 0x63, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2f, 0x70, 0x62, 0x2f, 0x70, 0x61,
	0x72, 0x69, 0x74, 0x79, 0x76, 0x30, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_parity_v0_Packet_proto_rawDescOnce sync.Once
	file_parity_v0_Packet_proto_rawDescData = file_parity_v0_Packet_proto_rawDesc
)

func file_parity_v0_Packet_proto_rawDescGZIP() []byte {
	file_parity_v0_Packet_proto_rawDescOnce.Do(func() {
		file_parity_v0_Packet_proto_rawDescData = protoimpl.X.CompressGZIP(file_parity_v0_Packet_proto_rawDescData)
	})
	return file_parity_v0_Packet_proto_rawDescData
}

var file_parity_v0_Packet_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_parity_v0_Packet_proto_goTypes = []interface{}{
	(*IndexPacket)(nil),      // 0: xorkevin.bitcensus.parity.v0.IndexPacket
	(*InputFile)(nil),        // 1: xorkevin.bitcensus.parity.v0.InputFile
	(*ShardConfig)(nil),      // 2: xorkevin.bitcensus.parity.v0.ShardConfig
	(*CodeMatrixConfig)(nil), // 3: xorkevin.bitcensus.parity.v0.CodeMatrixConfig
	(*BlockSet)(nil),         // 4: xorkevin.bitcensus.parity.v0.BlockSet
	(*Block)(nil),            // 5: xorkevin.bitcensus.parity.v0.Block
}
var file_parity_v0_Packet_proto_depIdxs = []int32{
	1, // 0: xorkevin.bitcensus.parity.v0.IndexPacket.input_file:type_name -> xorkevin.bitcensus.parity.v0.InputFile
	2, // 1: xorkevin.bitcensus.parity.v0.IndexPacket.shard_config:type_name -> xorkevin.bitcensus.parity.v0.ShardConfig
	4, // 2: xorkevin.bitcensus.parity.v0.IndexPacket.block_set:type_name -> xorkevin.bitcensus.parity.v0.BlockSet
	3, // 3: xorkevin.bitcensus.parity.v0.ShardConfig.code_matrix_config:type_name -> xorkevin.bitcensus.parity.v0.CodeMatrixConfig
	5, // 4: xorkevin.bitcensus.parity.v0.BlockSet.input:type_name -> xorkevin.bitcensus.parity.v0.Block
	5, // 5: xorkevin.bitcensus.parity.v0.BlockSet.parity:type_name -> xorkevin.bitcensus.parity.v0.Block
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_parity_v0_Packet_proto_init() }
func file_parity_v0_Packet_proto_init() {
	if File_parity_v0_Packet_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_parity_v0_Packet_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IndexPacket); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_parity_v0_Packet_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InputFile); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_parity_v0_Packet_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ShardConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_parity_v0_Packet_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CodeMatrixConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_parity_v0_Packet_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BlockSet); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_parity_v0_Packet_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Block); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_parity_v0_Packet_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_parity_v0_Packet_proto_goTypes,
		DependencyIndexes: file_parity_v0_Packet_proto_depIdxs,
		MessageInfos:      file_parity_v0_Packet_proto_msgTypes,
	}.Build()
	File_parity_v0_Packet_proto = out.File
	file_parity_v0_Packet_proto_rawDesc = nil
	file_parity_v0_Packet_proto_goTypes = nil
	file_parity_v0_Packet_proto_depIdxs = nil
}
