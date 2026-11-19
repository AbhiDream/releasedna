"""Separate process + wall deadline. This is not a filesystem/network sandbox."""
import multiprocessing


def _child(connection,operation,payload,timeout):
    limits={'separate_process':True,'wall_timeout_seconds':timeout,'os_memory_limit':False,'network_isolation':False}
    try:
        import os
        if os.name!='nt':
            import resource
            resource.setrlimit(resource.RLIMIT_AS,(768*1024*1024,768*1024*1024))
            resource.setrlimit(resource.RLIMIT_CPU,(120,120))
            limits['os_memory_limit']=True
        if operation=='registry':
            from app.services.scan import scan
            result=scan(**payload)
        elif operation=='local':
            from app.services.local_compare import compare_archives
            result=compare_archives(**payload)
        else: raise ValueError('Unknown inspection operation')
        result['execution_boundary']=limits
        connection.send(('ok',result))
    except Exception as exc:
        try: connection.send(('error',f'{type(exc).__name__}: {exc}'))
        except (BrokenPipeError,EOFError,OSError): pass
    finally: connection.close()


def bounded_inspection(operation,payload,timeout=150):
    context=multiprocessing.get_context('spawn')
    receiver,sender=context.Pipe(duplex=False)
    process=context.Process(target=_child,args=(sender,operation,payload,timeout),daemon=True)
    process.start();sender.close()
    try:
        if not receiver.poll(timeout): raise TimeoutError('Inspection worker exceeded wall-clock deadline')
        try: status,value=receiver.recv()
        except EOFError as exc: raise RuntimeError('Inspection worker exited before committing a result') from exc
        if status!='ok': raise ValueError(value)
        return value
    finally:
        receiver.close()
        process.join(timeout=1)
        if process.is_alive():process.terminate();process.join(timeout=3)
        if process.is_alive():process.kill();process.join()
