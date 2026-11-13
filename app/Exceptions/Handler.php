<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Illuminate\Support\Arr;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Throwable;
use Facade\Ignition\Exceptions\ViewException;

class Handler extends ExceptionHandler
{
    /**
     * A list of the exception types that are not reported.
     *
     * @var array
     */
    protected $dontReport = [
        //
    ];

    /**
     * A list of the inputs that are never flashed for validation exceptions.
     *
     * @var array
     */
    protected $dontFlash = [
        'password',
        'password_confirmation',
    ];

    /**
     * Report or log an exception.
     *
     * @param  \Throwable  $exception
     * @return void
     *
     * @throws \Throwable
     */
    public function report(Throwable $exception)
    {
        if ($this->isDatabaseConnectionFailure($exception)) {
            return;
        }
        parent::report($exception);
    }

    /**
     * Render an exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Throwable  $exception
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \Throwable
     */
    public function render($request, Throwable $exception)
    {
        if ($this->isDatabaseConnectionFailure($exception)) {
            $request->attributes->set('database_connection_failed', true);
            return response()->json(['message' => 'Database temporarily unavailable'], 503)->header('Retry-After', '5');
        }
        if ($exception instanceof ViewException) {
            abort(500, "主题渲染失败。如更新主题，参数可能发生变化请重新配置主题后再试。");
        }
        return parent::render($request, $exception);
    }


    public function isDatabaseConnectionFailure(Throwable $exception): bool
    {
        for ($depth = 0; $exception && $depth < 5; $depth++, $exception = $exception->getPrevious()) {
            if ($exception instanceof \PDOException) {
                $state = (string)($exception->errorInfo[0] ?? $exception->getCode());
                $code = (int)($exception->errorInfo[1] ?? $exception->getCode());
                if (substr($state, 0, 2) === '08' || in_array($code, [1040, 2002, 2003, 2006, 2013], true)) {
                    return true;
                }
            }
        }
        return false;
    }

    protected function convertExceptionToArray(Throwable $e)
    {
        return config('app.debug') ? [
            'message' => $e->getMessage(),
            'exception' => get_class($e),
            'file' => $e->getFile(),
            'line' => $e->getLine(),
            'trace' => collect($e->getTrace())->map(function ($trace) {
                return Arr::except($trace, ['args']);
            })->all(),
        ] : [
            'message' => $this->isHttpException($e) ? $e->getMessage() : __("Uh-oh, we've had some problems, we're working on it."),
        ];
    }
}
