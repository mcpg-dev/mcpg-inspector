'use client';

import * as React from 'react';

import { cn } from '../lib/utils';

// Dependency-free stand-in for @radix-ui/react-avatar with the same
// composable API: the fallback renders until the image has loaded.
type AvatarImageStatus = 'loading' | 'loaded' | 'error';

const AvatarContext = React.createContext<{
  status: AvatarImageStatus;
  setStatus: (status: AvatarImageStatus) => void;
}>({ status: 'loading', setStatus: () => {} });

const Avatar = React.forwardRef<HTMLSpanElement, React.HTMLAttributes<HTMLSpanElement>>(
  ({ className, ...props }, ref) => {
    const [status, setStatus] = React.useState<AvatarImageStatus>('loading');
    const value = React.useMemo(() => ({ status, setStatus }), [status]);
    return (
      <AvatarContext.Provider value={value}>
        <span
          ref={ref}
          className={cn('relative flex h-10 w-10 shrink-0 overflow-hidden rounded-full', className)}
          {...props}
        />
      </AvatarContext.Provider>
    );
  },
);
Avatar.displayName = 'Avatar';

const AvatarImage = React.forwardRef<HTMLImageElement, React.ImgHTMLAttributes<HTMLImageElement>>(
  ({ className, src, onLoad, onError, ...props }, forwardedRef) => {
    const { status, setStatus } = React.useContext(AvatarContext);
    const innerRef = React.useRef<HTMLImageElement>(null);

    React.useImperativeHandle(forwardedRef, () => innerRef.current as HTMLImageElement);

    // A cached image can finish before React attaches the load handler;
    // `complete` catches that so the fallback doesn't stick.
    React.useEffect(() => {
      if (!src) {
        setStatus('error');
        return;
      }
      const img = innerRef.current;
      setStatus(img?.complete && img.naturalWidth > 0 ? 'loaded' : 'loading');
    }, [src, setStatus]);

    if (!src || status === 'error') return null;
    return (
      <img
        ref={innerRef}
        src={src}
        className={cn('aspect-square h-full w-full object-cover', status !== 'loaded' && 'invisible', className)}
        onLoad={(event) => {
          setStatus('loaded');
          onLoad?.(event);
        }}
        onError={(event) => {
          setStatus('error');
          onError?.(event);
        }}
        {...props}
      />
    );
  },
);
AvatarImage.displayName = 'AvatarImage';

const AvatarFallback = React.forwardRef<HTMLSpanElement, React.HTMLAttributes<HTMLSpanElement>>(
  ({ className, ...props }, ref) => {
    const { status } = React.useContext(AvatarContext);
    if (status === 'loaded') return null;
    return (
      <span
        ref={ref}
        className={cn(
          'absolute inset-0 flex select-none items-center justify-center rounded-full bg-muted text-sm font-medium text-muted-foreground',
          className,
        )}
        {...props}
      />
    );
  },
);
AvatarFallback.displayName = 'AvatarFallback';

export { Avatar, AvatarImage, AvatarFallback };
