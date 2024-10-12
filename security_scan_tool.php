<?php

// مسح الملفات في الموقع لكشف الثغرات الشائعة مع واجهة مستخدم بلوحة تحكم

// دالة لإرجاع قائمة بالمجلدات في المسار المحدد
function getDirectories($directory) {
    $directories = [];
    $iterator = new DirectoryIterator($directory);
    foreach ($iterator as $dir) {
        if ($dir->isDir() && !$dir->isDot()) {
            $directories[] = $dir->getPathname();
        }
    }
    return $directories;
}

// دالة لإرجاع قائمة بالملفات في المسار المحدد
function getFiles($directory) {
    $files = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));
    foreach ($iterator as $file) {
        if ($file->isFile() && preg_match('/\.(php|html|js)$/i', $file->getFilename())) {
            $files[] = $file->getPathname();
        }
    }
    return $files;
}

// دالة لفحص الملف بحثًا عن أنماط ثغرات شائعة
function checkFileForVulnerabilities($filePath) {
    $content = file($filePath);
    $vulnerabilities = [];

    // الأنماط الشائعة للثغرات (Regex)
    $patterns = [
        '/eval\s*\(/i' => 'استخدام eval() يمكن أن يكون خطيرًا ويسمح بتنفيذ أكواد ضارة.',
        '/base64_decode\s*\(/i' => 'استخدام base64_decode() قد يخفي تعليمات برمجية ضارة.',
        '/shell_exec\s*\(/i' => 'استخدام shell_exec() يمكن أن يؤدي إلى تنفيذ أوامر نظام.',
        '/\$_(GET|POST|REQUEST|COOKIE)\s*\[/i' => 'الوصول المباشر إلى المدخلات بدون تصفية يمكن أن يؤدي إلى ثغرات مثل SQL Injection أو XSS.',
        '/preg_replace\s*\(([^,]+),\s*e\s*,/i' => 'استخدام preg_replace مع معدل "e" يمكن أن يؤدي إلى تنفيذ تعليمات برمجية ضارة.',
    ];

    // البحث عن الثغرات في المحتوى
    foreach ($patterns as $pattern => $message) {
        foreach ($content as $lineNumber => $line) {
            if (preg_match($pattern, $line)) {
                $vulnerabilities[] = "{$message} في السطر رقم " . ($lineNumber + 1);
            }
        }
    }

    return $vulnerabilities;
}

// واجهة المستخدم لعرض الملفات ونتائج الفحص
$directories = getDirectories(__DIR__);
$results = [];
$selectedDirectory = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['scan_directory'])) {
    $selectedDirectory = $_POST['scan_directory'];
    $files = getFiles($selectedDirectory);

    foreach ($files as $file) {
        $vulnerabilities = checkFileForVulnerabilities($file);
        if (!empty($vulnerabilities)) {
            $results[$file] = $vulnerabilities;
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ar">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>فحص الثغرات الأمنية</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Cairo&display=swap" rel="stylesheet">
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: 'Cairo', sans-serif;
            text-align: right;
        }
        .progress {
            height: 30px;
        }
    </style>
</head>
<body dir="rtl">
    <div class="container mt-5">
        <h2 class="text-center">أداة فحص الثغرات الأمنية في الملفات</h2>
        <form method="POST" class="my-4">
            <div class="form-group">
                <label for="scan_directory">حدد المجلد المراد فحصه:</label>
                <select id="scan_directory" name="scan_directory" class="form-control" required>
                    <option value="">اختر المجلد</option>
                    <?php foreach ($directories as $directory): ?>
                        <option value="<?= htmlspecialchars($directory) ?>" <?= ($selectedDirectory === $directory) ? 'selected' : '' ?>>
                            <?= htmlspecialchars(basename($directory)) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <button type="submit" class="btn btn-primary">فحص المجلد</button>
        </form>

        <?php if (isset($results) && !empty($results)): ?>
            <h3 class="mt-5">نتائج الفحص:</h3>
            <div class="progress mb-4">
                <div id="progress-bar" class="progress-bar bg-success" role="progressbar" style="width: 0%;" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"></div>
            </div>
            <div class="list-group">
                <?php foreach ($results as $file => $vulnerabilities): ?>
                    <div class="list-group-item">
                        <strong>الملف:</strong> <?= htmlspecialchars($file) ?><br>
                        <?php foreach ($vulnerabilities as $vulnerability): ?>
                            <span class="text-danger">- <?= htmlspecialchars($vulnerability) ?></span><br>
                        <?php endforeach; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>

    <footer class="text-center mt-5">
        <p>RAKAN ALYAMI - Telegram: @r7000r - Email: rakan7777@gmail.com</p>
    </footer>

    <script>
        $(document).ready(function() {
            <?php if (isset($results) && !empty($results)): ?>
                var progressBar = $('#progress-bar');
                var totalFiles = <?= count($results) ?>;
                var processedFiles = 0;

                progressBar.css('width', '0%');
                progressBar.attr('aria-valuenow', 0);

                <?php foreach ($results as $file => $vulnerabilities): ?>
                    processedFiles++;
                    var progress = Math.round((processedFiles / totalFiles) * 100);
                    progressBar.css('width', progress + '%');
                    progressBar.attr('aria-valuenow', progress);
                <?php endforeach; ?>
            <?php endif; ?>
        });
    </script>
</body>
</html>