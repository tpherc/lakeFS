import React, { useContext } from 'react';
import { useAPI } from '../../hooks/api';
import { objects, qs } from '../../api';
import ReactDiffViewer, { DiffMethod } from 'react-diff-viewer-continued';
import { AlertError, Loading } from '../controls';
import { humanSize } from './tree';
import Alert from 'react-bootstrap/Alert';
import Card from 'react-bootstrap/Card';
import { InfoIcon } from '@primer/octicons-react';
import { useConfigContext } from '../../hooks/configProvider';
import { AppContext } from '../../hooks/appContext';
import { useRefs } from '../../hooks/repo';
import { getObjectStorageConfig } from '../../../pages/repositories/repository/utils';

const maxDiffSizeBytes = 120 << 10;
const supportedReadableFormats = [
    'txt',
    'text',
    'md',
    'csv',
    'tsv',
    'yaml',
    'yml',
    'json',
    'jsonl',
    'ndjson',
    'geojson',
];
const imageExtensions = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'];

export const ObjectsDiff = ({ diffType, repoId, leftRef, rightRef, path }) => {
    const { state } = useContext(AppContext);
    const { repo, error: repoError, loading: repoLoading } = useRefs();
    const { config, error: configsError, loading: configLoading } = useConfigContext();
    const hooksLoading = repoLoading || configLoading;
    const hooksError = hooksLoading ? null : repoError || configsError;

    const hasLeft = ['changed', 'conflict', 'removed'].includes(diffType);
    const hasRight = ['changed', 'conflict', 'added'].includes(diffType);
    const left = useAPI(
        () => (hasLeft ? objects.getStat(repoId, leftRef, path) : Promise.resolve(null)),
        [repoId, leftRef, path, hasLeft],
    );
    const right = useAPI(
        () => (hasRight ? objects.getStat(repoId, rightRef, path) : Promise.resolve(null)),
        [repoId, rightRef, path, hasRight],
    );
    if (hooksError) return <AlertError error={hooksError} />;
    if (!hasLeft && !hasRight) return <AlertError error={'Unsupported diff type ' + diffType} />;
    if (hooksLoading || left.loading || right.loading) return <Loading />;
    const err = left.error || right.error;
    if (err) return <AlertError error={err} />;

    const readable = readableObject(path);
    const leftStat = left && left.response;
    const rightStat = right && right.response;
    if (!readable) {
        return <NoContentDiff left={leftStat} right={rightStat} diffType={diffType} />;
    }
    const objectTooBig =
        (leftStat && leftStat.size_bytes > maxDiffSizeBytes) || (rightStat && rightStat.size_bytes > maxDiffSizeBytes);
    if (objectTooBig) {
        return (
            <AlertError
                error={
                    path +
                    ' is too big (> ' +
                    humanSize(maxDiffSizeBytes) +
                    '). To view its diff please download' +
                    ' the objects and use an external diff tool.'
                }
            />
        );
    }
    const leftSize = leftStat && leftStat.size_bytes;
    const rightSize = rightStat && rightStat.size_bytes;
    return (
        <ContentDiff
            leftPresign={getObjectStorageConfig(config?.storages, repo, leftStat)?.pre_sign_support_ui ?? false}
            rightPresign={getObjectStorageConfig(config?.storages, repo, rightStat)?.pre_sign_support_ui ?? false}
            repoId={repoId}
            path={path}
            leftRef={hasLeft ? leftRef : null}
            rightRef={hasRight ? rightRef : null}
            leftSize={leftSize}
            rightSize={rightSize}
            diffType={diffType}
            settings={state.settings}
        />
    );
};

function readableObject(path) {
    if (isImage(path)) return true;
    for (const ext of supportedReadableFormats) {
        if (path.endsWith('.' + ext)) {
            return true;
        }
    }
    return false;
}

const NoContentDiff = ({ left, right, diffType }) => {
    const supportedFileExtensions = supportedReadableFormats.map((fileType) => `.${fileType}`);
    return (
        <div>
            <span>
                <StatDiff left={left} right={right} diffType={diffType} />
            </span>
            <span>
                <Alert variant="light">
                    <InfoIcon />{' '}
                    {`lakeFS supports content diff for ${supportedFileExtensions.join(',')} file formats only`}
                </Alert>
            </span>
        </div>
    );
};

const ContentDiff = ({
    leftPresign,
    rightPresign,
    repoId,
    path,
    leftRef,
    rightRef,
    leftSize,
    rightSize,
    diffType,
    settings,
}) =>
    isImage(path) ? (
        <ImageCardDiff
            leftPresign={leftPresign}
            rightPresign={rightPresign}
            repoId={repoId}
            path={path}
            leftRef={leftRef}
            rightRef={rightRef}
            leftSize={leftSize}
            rightSize={rightSize}
            diffType={diffType}
        />
    ) : (
        <TextDiff
            leftPresign={leftPresign}
            rightPresign={rightPresign}
            repoId={repoId}
            path={path}
            leftRef={leftRef}
            rightRef={rightRef}
            leftSize={leftSize}
            rightSize={rightSize}
            diffType={diffType}
            settings={settings.darkMode}
        />
    );

const TextDiff = ({
    leftPresign,
    rightPresign,
    repoId,
    path,
    leftRef,
    rightRef,
    leftSize,
    rightSize,
    diffType,
    isDarkMode,
}) => {
    const left = useAPI(
        () => (leftRef ? objects.get(repoId, leftRef, path, leftPresign) : Promise.resolve(null)),
        [repoId, leftRef, path, leftPresign],
    );
    const right = useAPI(
        () => (rightRef ? objects.get(repoId, rightRef, path, rightPresign) : Promise.resolve(null)),
        [repoId, rightRef, path, rightPresign],
    );

    if ((left && left.loading) || (right && right.loading)) return <Loading />;
    const err = (left && left.error) || (right && right.error);
    if (err) return <AlertError error={err} />;

    return (
        <div>
            <DiffSizeReport leftSize={leftSize} rightSize={rightSize} diffType={diffType} />
            <ReactDiffViewer
                oldValue={left?.response}
                newValue={right?.response}
                splitView={false}
                useDarkTheme={isDarkMode}
                compareMethod={DiffMethod.WORDS}
            />
        </div>
    );
};

const ImageCardDiff = ({
    leftPresign,
    rightPresign,
    repoId,
    path,
    leftRef,
    rightRef,
    leftSize,
    rightSize,
    diffType,
}) => {
    const oldUrl = leftRef && buildUrl(repoId, leftRef, qs({ path, presign: leftPresign }));
    const newUrl = rightRef && buildUrl(repoId, rightRef, qs({ path, presign: rightPresign }));

    return (
        <div>
            <ImageDiffSummary leftSize={leftSize} rightSize={rightSize} diffType={diffType} />
            <div className="image-diff-card-container">
                {oldUrl && (
                    <Card className="image-diff-card-flex">
                        <Card.Header className="text-danger text-center image-diff-header-deleted">Deleted</Card.Header>
                        <Card.Body className="d-flex overflow-auto justify-content-center p-3">
                            <img className="image-diff-card" src={oldUrl} alt="old" />
                        </Card.Body>
                    </Card>
                )}
                {newUrl && (
                    <Card className="image-diff-card-flex">
                        <Card.Header className="text-success text-center image-diff-header-added">Added</Card.Header>
                        <Card.Body className="d-flex overflow-auto justify-content-center p-3">
                            <img className="image-diff-card" src={newUrl} alt="new" />
                        </Card.Body>
                    </Card>
                )}
            </div>
        </div>
    );
};

function validateDiffInput(left, right, diffType) {
    switch (diffType) {
        case 'changed':
            if (!left && !right) return <AlertError error={'Invalid diff input'} />;
            break;
        case 'added':
            if (!right) return <AlertError error={'Invalid diff input: right hand-side is missing'} />;
            break;
        case 'removed':
            if (!left) return <AlertError error={'Invalid diff input: left hand-side is missing'} />;
            break;
        case 'conflict':
            break;
        default:
            return <AlertError error={'Unknown diff type: ' + diffType} />;
    }
}

const StatDiff = ({ left, right, diffType }) => {
    const err = validateDiffInput(left, right, diffType);
    if (err) return err;
    const rightSize = right && right.size_bytes;
    const leftSize = left && left.size_bytes;
    return (
        <>
            <div className={'stats-diff-block'}>
                <DiffSizeReport leftSize={leftSize} rightSize={rightSize} diffType={diffType} />
            </div>
        </>
    );
};

const DiffSizeReport = ({ leftSize, rightSize, diffType }) => {
    let label = diffType;
    let size;
    switch (diffType) {
        case 'changed':
            size = leftSize - rightSize;
            if (size === 0) {
                return (
                    <div>
                        <span className="unchanged">identical file size</span>
                    </div>
                );
            }
            if (size < 0) {
                size = -size;
                label = 'added';
            } else {
                label = 'removed';
            }
            break;
        case 'conflict': // conflict will compare left and right. further details: https://github.com/treeverse/lakeFS/issues/3269
            return (
                <div>
                    <span className={label}>{label} </span>
                    <span>both source and destination file were changed.</span>
                    <span className={'diff-size'}> Source: {humanSize(leftSize)}</span>
                    <span> in size, </span>
                    <span className={'diff-size'}> Destination: {humanSize(rightSize)}</span>
                    <span> in size</span>
                </div>
            );
        case 'added':
            size = rightSize;
            break;
        case 'removed':
            size = leftSize;
            break;
        default:
            return <AlertError error={'Unknown diff type: ' + diffType} />;
    }

    return (
        <div>
            <span className={label}>{label} </span>
            <span className={'diff-size'}>{humanSize(size)}</span>
            <span> in size</span>
        </div>
    );
};

const ImageDiffSummary = ({ leftSize, rightSize, diffType }) => {
    let diffValue = '';
    let cls = '';
    if (diffType === 'changed' && leftSize !== null && rightSize !== null) {
        const d = rightSize - leftSize;
        const sign = d > 0 ? '+' : '-';
        const abs = Math.abs(d);
        const pct = leftSize > 0 ? ((abs / leftSize) * 100).toFixed(1) : '0.0';
        cls = d > 0 ? 'text-success' : 'text-danger';
        diffValue = `${sign}${humanSize(abs)} (${pct}%)`;
    } else if (diffType === 'added') {
        cls = 'text-success';
        diffValue = `+${humanSize(rightSize)}`;
    } else if (diffType === 'removed') {
        cls = 'text-danger';
        diffValue = `-${humanSize(leftSize)}`;
    }
    return <div className={`text-center mb-2 ${cls} image-diff-summary`}>{diffValue}</div>;
};

const isImage = (path) => imageExtensions.some((ext) => path.toLowerCase().endsWith('.' + ext));

const buildUrl = (repoId, ref, query) =>
    `/api/v1/repositories/${encodeURIComponent(repoId)}/refs/${encodeURIComponent(ref)}/objects?${query}`;
