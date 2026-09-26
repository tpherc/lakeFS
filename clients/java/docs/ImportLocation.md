

# ImportLocation


## Properties

| Name | Type | Description | Notes |
|------------ | ------------- | ------------- | -------------|
|**storageId** | **String** | Configured backend containing this source. Omitted or empty uses the repository backend. |  [optional] |
|**type** | [**TypeEnum**](#TypeEnum) | Path type, can either be &#39;common_prefix&#39; or &#39;object&#39; |  |
|**path** | **String** | A source location to a &#39;common_prefix&#39; or to a single object. Must match the selected backend&#39;s native address format. |  |
|**destination** | **String** | Destination for the imported objects on the branch. Must be a relative path to the branch. If the type is an &#39;object&#39;, the destination is the exact object name under the branch. If the type is a &#39;common_prefix&#39;, the destination is the prefix under the branch.  |  |



## Enum: TypeEnum

| Name | Value |
|---- | -----|
| COMMON_PREFIX | &quot;common_prefix&quot; |
| OBJECT | &quot;object&quot; |



