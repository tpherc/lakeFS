type StorageBackend = {
    blockstore_id?: string;
    blockstore_description?: string | null;
};

export function storageBackendLabel(storage: StorageBackend): string {
    const id = storage.blockstore_id || '';
    const description = storage.blockstore_description;
    if (!description || description === id) return id;
    return id ? `${description} · ${id}` : description;
}
