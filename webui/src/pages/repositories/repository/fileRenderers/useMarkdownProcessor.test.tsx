import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { expect, test } from 'vitest';
import { useMarkdownProcessor } from './useMarkdownProcessor';

const Preview = ({ repo, reference, path }: { repo: string; reference: string; path: string }) =>
    useMarkdownProcessor('![relative](./image.png)\n![foreign](lakefs://other/main/image.png)', repo, reference, path);

test('Markdown images use proxied access and refresh when the same text moves', async () => {
    const { rerender } = render(<Preview repo="repo" reference="before" path="old/readme.md" />);
    await waitFor(() =>
        expect(screen.getByAltText('relative').getAttribute('src')).toContain(
            'refs/before/objects?path=old%2Fimage.png',
        ),
    );
    expect(screen.getByAltText('foreign').getAttribute('src')).toBe(
        '/api/v1/repositories/other/refs/main/objects?path=image.png',
    );
    rerender(<Preview repo="new-repo" reference="after" path="new/readme.md" />);
    await waitFor(() =>
        expect(screen.getByAltText('relative').getAttribute('src')).toContain(
            '/repositories/new-repo/refs/after/objects?path=new%2Fimage.png',
        ),
    );
});
