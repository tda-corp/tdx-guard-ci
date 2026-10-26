<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;

class Deploy extends Command
{
    public function handle(): void
    {
        // ok: php.laravel-artisan-command-over-http
        Artisan::call('migrate', ['--force' => true]);
    }
}
