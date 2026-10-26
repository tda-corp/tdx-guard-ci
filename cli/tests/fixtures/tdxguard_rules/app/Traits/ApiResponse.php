<?php

namespace App\Traits;

use Throwable;

trait ApiResponse
{
    protected function errorResponse(Throwable $e, int $status = 500)
    {
        $errors = [
            'message' => $e->getMessage(),
            'file' => $e->getFile(),
            'line' => $e->getLine(),
        ];

        // ruleid: php.exception-details-in-response
        return response()->json(['success' => false, 'errors' => $errors], $status);
    }

    protected function traceResponse(Throwable $e)
    {
        // ruleid: php.exception-details-in-response
        return response()->json(['trace' => $e->getTraceAsString()], 500);
    }

    protected function debugResponse(Throwable $e)
    {
        $errors = ['message' => 'Server error'];
        if (config('app.debug')) {
            $errors['file'] = $e->getFile();
            $errors['line'] = $e->getLine();
        }

        // ok: php.exception-details-in-response
        return response()->json(['errors' => $errors], 500);
    }

    protected function stagingResponse(Throwable $e)
    {
        $results = ['message' => 'Server error'];
        if (config('const.app_env') !== 'production') {
            $results = ['message' => 'Server error', 'file' => $e->getFile(), 'line' => $e->getLine()];
        }

        // ok: php.exception-details-in-response
        return response()->json($results, 500);
    }

    protected function environmentResponse(Throwable $e)
    {
        $results = ['message' => 'Server error'];
        if (app()->environment('local', 'testing')) {
            $results['trace'] = $e->getTraceAsString();
        }

        // ok: php.exception-details-in-response
        return response()->json($results, 500);
    }

    protected function statusZeroResponse(Throwable $e, int $statusCode)
    {
        switch ($statusCode) {
            case 0:
                $response['message'] = $e->getMessage();
                $response['errors'] = $e->getTraceAsString();
                break;
            default:
                $response['message'] = 'Unprocessable';
                break;
        }

        // ruleid: php.exception-details-in-response
        return response()->json($response, 422);
    }

    protected function loggedResponse(Throwable $e)
    {
        \Log::error('failed', ['file' => $e->getFile(), 'line' => $e->getLine()]);

        // ok: php.exception-details-in-response
        return response()->json(['message' => 'Server error'], 500);
    }
}
