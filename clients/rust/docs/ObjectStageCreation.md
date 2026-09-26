# ObjectStageCreation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**storage_id** | Option<**String**> | Configured backend containing the source object. Omitted or empty uses the repository backend. | [optional]
**physical_address** | **String** |  | 
**checksum** | **String** |  | 
**size_bytes** | **i64** |  | 
**mtime** | Option<**i64**> | Unix Epoch in seconds | [optional]
**metadata** | Option<**std::collections::HashMap<String, String>**> |  | [optional]
**content_type** | Option<**String**> | Object media type | [optional]
**force** | Option<**bool**> |  | [optional][default to false]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


