<?php

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;

Route::get('/run-migrate', function () {
    // ruleid: php.laravel-artisan-command-over-http
    Artisan::call('migrate', ['--force' => true]);

    return response()->json(['status' => 'success', 'output' => Artisan::output()]);
});

Route::post('/maintenance', function () {
    // ruleid: php.laravel-artisan-command-over-http
    \Illuminate\Support\Facades\Artisan::call('down');
});

Route::get('/inspire', function () {
    // ok: php.laravel-artisan-command-over-http
    Artisan::call('inspire');
});
