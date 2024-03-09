// @generated by protoc-gen-es v1.6.0 with parameter "target=ts,import_extension="
// @generated from file redpanda/api/console/v1alpha1/list_messages.proto (package redpanda.api.console.v1alpha1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3, protoInt64 } from "@bufbuild/protobuf";
import { CompressionType, KafkaRecordHeader, PayloadEncoding, TroubleshootReport } from "./common_pb";

/**
 * ListMessagesRequest is the request for ListMessages call.
 *
 * @generated from message redpanda.api.console.v1alpha1.ListMessagesRequest
 */
export class ListMessagesRequest extends Message<ListMessagesRequest> {
  /**
   * Topic name.
   *
   * @generated from field: string topic = 1;
   */
  topic = "";

  /**
   * Start offset. -1 for recent (newest - results), -2 for oldest offset, -3 for newest, -4 for timestamp.
   *
   * @generated from field: sint64 start_offset = 2;
   */
  startOffset = protoInt64.zero;

  /**
   * Start offset by unix timestamp in ms (only considered if start offset is set to -4).
   *
   * @generated from field: int64 start_timestamp = 3;
   */
  startTimestamp = protoInt64.zero;

  /**
   * -1 for all partition ids
   *
   * @generated from field: int32 partition_id = 4;
   */
  partitionId = 0;

  /**
   * Maximum number of results
   *
   * @generated from field: int32 max_results = 5;
   */
  maxResults = 0;

  /**
   * Base64 encoded code
   *
   * @generated from field: string filter_interpreter_code = 6;
   */
  filterInterpreterCode = "";

  /**
   * Enterprise may only be set in the Enterprise mode. The JSON deserialization is deferred.
   *
   * @generated from field: bytes enterprise = 7;
   */
  enterprise = new Uint8Array(0);

  /**
   * Optionally include troubleshooting data in the response.
   *
   * @generated from field: bool troubleshoot = 8;
   */
  troubleshoot = false;

  /**
   * Optionally include original raw payload.
   *
   * @generated from field: bool include_original_raw_payload = 9;
   */
  includeOriginalRawPayload = false;

  /**
   * Optionally specify key payload deserialization strategy to use.
   *
   * @generated from field: optional redpanda.api.console.v1alpha1.PayloadEncoding key_deserializer = 10;
   */
  keyDeserializer?: PayloadEncoding;

  /**
   * Optionally specify value payload deserialization strategy to use.
   *
   * @generated from field: optional redpanda.api.console.v1alpha1.PayloadEncoding value_deserializer = 11;
   */
  valueDeserializer?: PayloadEncoding;

  /**
   * Optionally ignore configured maximum payload size limit.
   *
   * @generated from field: bool ignore_max_size_limit = 12;
   */
  ignoreMaxSizeLimit = false;

  constructor(data?: PartialMessage<ListMessagesRequest>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "redpanda.api.console.v1alpha1.ListMessagesRequest";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "topic", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "start_offset", kind: "scalar", T: 18 /* ScalarType.SINT64 */ },
    { no: 3, name: "start_timestamp", kind: "scalar", T: 3 /* ScalarType.INT64 */ },
    { no: 4, name: "partition_id", kind: "scalar", T: 5 /* ScalarType.INT32 */ },
    { no: 5, name: "max_results", kind: "scalar", T: 5 /* ScalarType.INT32 */ },
    { no: 6, name: "filter_interpreter_code", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 7, name: "enterprise", kind: "scalar", T: 12 /* ScalarType.BYTES */ },
    { no: 8, name: "troubleshoot", kind: "scalar", T: 8 /* ScalarType.BOOL */ },
    { no: 9, name: "include_original_raw_payload", kind: "scalar", T: 8 /* ScalarType.BOOL */ },
    { no: 10, name: "key_deserializer", kind: "enum", T: proto3.getEnumType(PayloadEncoding), opt: true },
    { no: 11, name: "value_deserializer", kind: "enum", T: proto3.getEnumType(PayloadEncoding), opt: true },
    { no: 12, name: "ignore_max_size_limit", kind: "scalar", T: 8 /* ScalarType.BOOL */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListMessagesRequest {
    return new ListMessagesRequest().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListMessagesRequest {
    return new ListMessagesRequest().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListMessagesRequest {
    return new ListMessagesRequest().fromJsonString(jsonString, options);
  }

  static equals(a: ListMessagesRequest | PlainMessage<ListMessagesRequest> | undefined, b: ListMessagesRequest | PlainMessage<ListMessagesRequest> | undefined): boolean {
    return proto3.util.equals(ListMessagesRequest, a, b);
  }
}

/**
 * ListMessagesResponse is the response for ListMessages call.
 *
 * @generated from message redpanda.api.console.v1alpha1.ListMessagesResponse
 */
export class ListMessagesResponse extends Message<ListMessagesResponse> {
  /**
   * The control message as we consume messages.
   *
   * @generated from oneof redpanda.api.console.v1alpha1.ListMessagesResponse.control_message
   */
  controlMessage: {
    /**
     * @generated from field: redpanda.api.console.v1alpha1.ListMessagesResponse.DataMessage data = 1;
     */
    value: ListMessagesResponse_DataMessage;
    case: "data";
  } | {
    /**
     * @generated from field: redpanda.api.console.v1alpha1.ListMessagesResponse.PhaseMessage phase = 2;
     */
    value: ListMessagesResponse_PhaseMessage;
    case: "phase";
  } | {
    /**
     * @generated from field: redpanda.api.console.v1alpha1.ListMessagesResponse.ProgressMessage progress = 3;
     */
    value: ListMessagesResponse_ProgressMessage;
    case: "progress";
  } | {
    /**
     * @generated from field: redpanda.api.console.v1alpha1.ListMessagesResponse.StreamCompletedMessage done = 4;
     */
    value: ListMessagesResponse_StreamCompletedMessage;
    case: "done";
  } | {
    /**
     * @generated from field: redpanda.api.console.v1alpha1.ListMessagesResponse.ErrorMessage error = 5;
     */
    value: ListMessagesResponse_ErrorMessage;
    case: "error";
  } | { case: undefined; value?: undefined } = { case: undefined };

  constructor(data?: PartialMessage<ListMessagesResponse>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "redpanda.api.console.v1alpha1.ListMessagesResponse";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "data", kind: "message", T: ListMessagesResponse_DataMessage, oneof: "control_message" },
    { no: 2, name: "phase", kind: "message", T: ListMessagesResponse_PhaseMessage, oneof: "control_message" },
    { no: 3, name: "progress", kind: "message", T: ListMessagesResponse_ProgressMessage, oneof: "control_message" },
    { no: 4, name: "done", kind: "message", T: ListMessagesResponse_StreamCompletedMessage, oneof: "control_message" },
    { no: 5, name: "error", kind: "message", T: ListMessagesResponse_ErrorMessage, oneof: "control_message" },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListMessagesResponse {
    return new ListMessagesResponse().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListMessagesResponse {
    return new ListMessagesResponse().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListMessagesResponse {
    return new ListMessagesResponse().fromJsonString(jsonString, options);
  }

  static equals(a: ListMessagesResponse | PlainMessage<ListMessagesResponse> | undefined, b: ListMessagesResponse | PlainMessage<ListMessagesResponse> | undefined): boolean {
    return proto3.util.equals(ListMessagesResponse, a, b);
  }
}

/**
 * Data control message.
 *
 * @generated from message redpanda.api.console.v1alpha1.ListMessagesResponse.DataMessage
 */
export class ListMessagesResponse_DataMessage extends Message<ListMessagesResponse_DataMessage> {
  /**
   * @generated from field: int32 partition_id = 1;
   */
  partitionId = 0;

  /**
   * @generated from field: int64 offset = 2;
   */
  offset = protoInt64.zero;

  /**
   * @generated from field: int64 timestamp = 3;
   */
  timestamp = protoInt64.zero;

  /**
   * @generated from field: redpanda.api.console.v1alpha1.CompressionType compression = 4;
   */
  compression = CompressionType.UNSPECIFIED;

  /**
   * @generated from field: bool is_transactional = 5;
   */
  isTransactional = false;

  /**
   * Kafka record headers.
   *
   * @generated from field: repeated redpanda.api.console.v1alpha1.KafkaRecordHeader headers = 6;
   */
  headers: KafkaRecordHeader[] = [];

  /**
   * Kafka key of the payload record.
   *
   * @generated from field: redpanda.api.console.v1alpha1.KafkaRecordPayload key = 7;
   */
  key?: KafkaRecordPayload;

  /**
   * Kafka value of the payload record.
   *
   * @generated from field: redpanda.api.console.v1alpha1.KafkaRecordPayload value = 8;
   */
  value?: KafkaRecordPayload;

  constructor(data?: PartialMessage<ListMessagesResponse_DataMessage>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "redpanda.api.console.v1alpha1.ListMessagesResponse.DataMessage";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "partition_id", kind: "scalar", T: 5 /* ScalarType.INT32 */ },
    { no: 2, name: "offset", kind: "scalar", T: 3 /* ScalarType.INT64 */ },
    { no: 3, name: "timestamp", kind: "scalar", T: 3 /* ScalarType.INT64 */ },
    { no: 4, name: "compression", kind: "enum", T: proto3.getEnumType(CompressionType) },
    { no: 5, name: "is_transactional", kind: "scalar", T: 8 /* ScalarType.BOOL */ },
    { no: 6, name: "headers", kind: "message", T: KafkaRecordHeader, repeated: true },
    { no: 7, name: "key", kind: "message", T: KafkaRecordPayload },
    { no: 8, name: "value", kind: "message", T: KafkaRecordPayload },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListMessagesResponse_DataMessage {
    return new ListMessagesResponse_DataMessage().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListMessagesResponse_DataMessage {
    return new ListMessagesResponse_DataMessage().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListMessagesResponse_DataMessage {
    return new ListMessagesResponse_DataMessage().fromJsonString(jsonString, options);
  }

  static equals(a: ListMessagesResponse_DataMessage | PlainMessage<ListMessagesResponse_DataMessage> | undefined, b: ListMessagesResponse_DataMessage | PlainMessage<ListMessagesResponse_DataMessage> | undefined): boolean {
    return proto3.util.equals(ListMessagesResponse_DataMessage, a, b);
  }
}

/**
 * Phase control message.
 *
 * @generated from message redpanda.api.console.v1alpha1.ListMessagesResponse.PhaseMessage
 */
export class ListMessagesResponse_PhaseMessage extends Message<ListMessagesResponse_PhaseMessage> {
  /**
   * The current phase.
   *
   * @generated from field: string phase = 1;
   */
  phase = "";

  constructor(data?: PartialMessage<ListMessagesResponse_PhaseMessage>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "redpanda.api.console.v1alpha1.ListMessagesResponse.PhaseMessage";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "phase", kind: "scalar", T: 9 /* ScalarType.STRING */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListMessagesResponse_PhaseMessage {
    return new ListMessagesResponse_PhaseMessage().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListMessagesResponse_PhaseMessage {
    return new ListMessagesResponse_PhaseMessage().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListMessagesResponse_PhaseMessage {
    return new ListMessagesResponse_PhaseMessage().fromJsonString(jsonString, options);
  }

  static equals(a: ListMessagesResponse_PhaseMessage | PlainMessage<ListMessagesResponse_PhaseMessage> | undefined, b: ListMessagesResponse_PhaseMessage | PlainMessage<ListMessagesResponse_PhaseMessage> | undefined): boolean {
    return proto3.util.equals(ListMessagesResponse_PhaseMessage, a, b);
  }
}

/**
 * Progress control message.
 *
 * @generated from message redpanda.api.console.v1alpha1.ListMessagesResponse.ProgressMessage
 */
export class ListMessagesResponse_ProgressMessage extends Message<ListMessagesResponse_ProgressMessage> {
  /**
   * Currently consumed messages.
   *
   * @generated from field: int64 messages_consumed = 1;
   */
  messagesConsumed = protoInt64.zero;

  /**
   * Currently consumed bytes.
   *
   * @generated from field: int64 bytes_consumed = 2;
   */
  bytesConsumed = protoInt64.zero;

  constructor(data?: PartialMessage<ListMessagesResponse_ProgressMessage>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "redpanda.api.console.v1alpha1.ListMessagesResponse.ProgressMessage";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "messages_consumed", kind: "scalar", T: 3 /* ScalarType.INT64 */ },
    { no: 2, name: "bytes_consumed", kind: "scalar", T: 3 /* ScalarType.INT64 */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListMessagesResponse_ProgressMessage {
    return new ListMessagesResponse_ProgressMessage().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListMessagesResponse_ProgressMessage {
    return new ListMessagesResponse_ProgressMessage().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListMessagesResponse_ProgressMessage {
    return new ListMessagesResponse_ProgressMessage().fromJsonString(jsonString, options);
  }

  static equals(a: ListMessagesResponse_ProgressMessage | PlainMessage<ListMessagesResponse_ProgressMessage> | undefined, b: ListMessagesResponse_ProgressMessage | PlainMessage<ListMessagesResponse_ProgressMessage> | undefined): boolean {
    return proto3.util.equals(ListMessagesResponse_ProgressMessage, a, b);
  }
}

/**
 * Stream completed control message.
 *
 * @generated from message redpanda.api.console.v1alpha1.ListMessagesResponse.StreamCompletedMessage
 */
export class ListMessagesResponse_StreamCompletedMessage extends Message<ListMessagesResponse_StreamCompletedMessage> {
  /**
   * Total elapsed time in milliseconds.
   *
   * @generated from field: int64 elapsed_ms = 1;
   */
  elapsedMs = protoInt64.zero;

  /**
   * Whether the call was cancelled.
   *
   * @generated from field: bool is_cancelled = 2;
   */
  isCancelled = false;

  /**
   * Total consumed messages.
   *
   * @generated from field: int64 messages_consumed = 3;
   */
  messagesConsumed = protoInt64.zero;

  /**
   * Total consumed bytes.
   *
   * @generated from field: int64 bytes_consumed = 4;
   */
  bytesConsumed = protoInt64.zero;

  constructor(data?: PartialMessage<ListMessagesResponse_StreamCompletedMessage>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "redpanda.api.console.v1alpha1.ListMessagesResponse.StreamCompletedMessage";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "elapsed_ms", kind: "scalar", T: 3 /* ScalarType.INT64 */ },
    { no: 2, name: "is_cancelled", kind: "scalar", T: 8 /* ScalarType.BOOL */ },
    { no: 3, name: "messages_consumed", kind: "scalar", T: 3 /* ScalarType.INT64 */ },
    { no: 4, name: "bytes_consumed", kind: "scalar", T: 3 /* ScalarType.INT64 */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListMessagesResponse_StreamCompletedMessage {
    return new ListMessagesResponse_StreamCompletedMessage().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListMessagesResponse_StreamCompletedMessage {
    return new ListMessagesResponse_StreamCompletedMessage().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListMessagesResponse_StreamCompletedMessage {
    return new ListMessagesResponse_StreamCompletedMessage().fromJsonString(jsonString, options);
  }

  static equals(a: ListMessagesResponse_StreamCompletedMessage | PlainMessage<ListMessagesResponse_StreamCompletedMessage> | undefined, b: ListMessagesResponse_StreamCompletedMessage | PlainMessage<ListMessagesResponse_StreamCompletedMessage> | undefined): boolean {
    return proto3.util.equals(ListMessagesResponse_StreamCompletedMessage, a, b);
  }
}

/**
 * Error control message.
 *
 * @generated from message redpanda.api.console.v1alpha1.ListMessagesResponse.ErrorMessage
 */
export class ListMessagesResponse_ErrorMessage extends Message<ListMessagesResponse_ErrorMessage> {
  /**
   * The error message.
   *
   * @generated from field: string message = 1;
   */
  message = "";

  constructor(data?: PartialMessage<ListMessagesResponse_ErrorMessage>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "redpanda.api.console.v1alpha1.ListMessagesResponse.ErrorMessage";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "message", kind: "scalar", T: 9 /* ScalarType.STRING */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ListMessagesResponse_ErrorMessage {
    return new ListMessagesResponse_ErrorMessage().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ListMessagesResponse_ErrorMessage {
    return new ListMessagesResponse_ErrorMessage().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ListMessagesResponse_ErrorMessage {
    return new ListMessagesResponse_ErrorMessage().fromJsonString(jsonString, options);
  }

  static equals(a: ListMessagesResponse_ErrorMessage | PlainMessage<ListMessagesResponse_ErrorMessage> | undefined, b: ListMessagesResponse_ErrorMessage | PlainMessage<ListMessagesResponse_ErrorMessage> | undefined): boolean {
    return proto3.util.equals(ListMessagesResponse_ErrorMessage, a, b);
  }
}

/**
 * KafkaRecordPayload is record payload representation.
 *
 * @generated from message redpanda.api.console.v1alpha1.KafkaRecordPayload
 */
export class KafkaRecordPayload extends Message<KafkaRecordPayload> {
  /**
   * Original raw binary payload.
   *
   * @generated from field: optional bytes original_payload = 1;
   */
  originalPayload?: Uint8Array;

  /**
   * Normalized user friendly representation of the payload.
   *
   * @generated from field: optional bytes normalized_payload = 2;
   */
  normalizedPayload?: Uint8Array;

  /**
   * Payload encoding if we have been able to detect.
   *
   * @generated from field: redpanda.api.console.v1alpha1.PayloadEncoding encoding = 3;
   */
  encoding = PayloadEncoding.UNSPECIFIED;

  /**
   * Optionally, the schema ID used to deserialized the message.
   *
   * @generated from field: optional int32 schema_id = 4;
   */
  schemaId?: number;

  /**
   * Payload size in bytes.
   *
   * @generated from field: int32 payload_size = 5;
   */
  payloadSize = 0;

  /**
   * If payload is too large for deserialization.
   *
   * @generated from field: bool is_payload_too_large = 6;
   */
  isPayloadTooLarge = false;

  /**
   * Troubleshooting data for debugging.
   *
   * @generated from field: repeated redpanda.api.console.v1alpha1.TroubleshootReport troubleshoot_report = 7;
   */
  troubleshootReport: TroubleshootReport[] = [];

  constructor(data?: PartialMessage<KafkaRecordPayload>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "redpanda.api.console.v1alpha1.KafkaRecordPayload";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "original_payload", kind: "scalar", T: 12 /* ScalarType.BYTES */, opt: true },
    { no: 2, name: "normalized_payload", kind: "scalar", T: 12 /* ScalarType.BYTES */, opt: true },
    { no: 3, name: "encoding", kind: "enum", T: proto3.getEnumType(PayloadEncoding) },
    { no: 4, name: "schema_id", kind: "scalar", T: 5 /* ScalarType.INT32 */, opt: true },
    { no: 5, name: "payload_size", kind: "scalar", T: 5 /* ScalarType.INT32 */ },
    { no: 6, name: "is_payload_too_large", kind: "scalar", T: 8 /* ScalarType.BOOL */ },
    { no: 7, name: "troubleshoot_report", kind: "message", T: TroubleshootReport, repeated: true },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): KafkaRecordPayload {
    return new KafkaRecordPayload().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): KafkaRecordPayload {
    return new KafkaRecordPayload().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): KafkaRecordPayload {
    return new KafkaRecordPayload().fromJsonString(jsonString, options);
  }

  static equals(a: KafkaRecordPayload | PlainMessage<KafkaRecordPayload> | undefined, b: KafkaRecordPayload | PlainMessage<KafkaRecordPayload> | undefined): boolean {
    return proto3.util.equals(KafkaRecordPayload, a, b);
  }
}

