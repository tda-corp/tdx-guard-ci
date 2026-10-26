<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class LogApiRequest
{
    public function handle(Request $request, Closure $next)
    {
        $body = $request->all();
        foreach (['password', 'token'] as $key) {
            unset($body[$key]);
        }
        // ruleid: php.laravel-request-body-logged
        Log::info('API request', ['url' => $request->fullUrl(), 'body' => $body]);

        // ruleid: php.laravel-request-body-logged
        Log::channel('api')->debug('API request', $request->input());

        // ruleid: php.laravel-request-body-logged
        logger('API request', request()->all());

        // ok: php.laravel-request-body-logged
        Log::info('API request', $request->only(['page', 'per_page']));

        // ok: php.laravel-request-body-logged
        Log::info('API request', ['url' => $request->fullUrl(), 'method' => $request->method()]);

        return $next($request);
    }
}
