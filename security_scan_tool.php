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

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] === 'scan_directory') {
        $selectedDirectory = $_POST['scan_directory'];
        $files = getFiles($selectedDirectory);
        header('Content-Type: application/json');
        echo json_encode(['files' => $files]);
        exit;
    }

    if ($_POST['action'] === 'scan_file') {
        $filePath = $_POST['file_path'];
        $vulnerabilities = checkFileForVulnerabilities($filePath);
        header('Content-Type: application/json');
        echo json_encode(['file' => $filePath, 'vulnerabilities' => $vulnerabilities]);
        exit;
    }
}

$directories = getDirectories(__DIR__);
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
        <form id="scanForm" class="my-4">
            <div class="form-group">
                <label for="scan_directory">حدد المجلد المراد فحصه:</label>
                <select id="scan_directory" name="scan_directory" class="form-control" required>
                    <option value="">اختر المجلد</option>
                    <?php foreach ($directories as $directory): ?>
                        <option value="<?= htmlspecialchars($directory) ?>">
                            <?= htmlspecialchars(basename($directory)) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <button type="submit" class="btn btn-primary">فحص المجلد</button>
        </form>

        <h3 class="mt-5">التقدم في الفحص:</h3>
        <div class="progress mb-4">
            <div id="progress-bar" class="progress-bar progress-bar-striped progress-bar-animated bg-success" role="progressbar" style="width: 0%;" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"></div>
        </div>
        <div id="results" class="mt-4"></div>
    </div>

    <footer class="text-center mt-5">
        <p>RAKAN ALYAMI - Telegram: @r7000r - Email: rakan7777@gmail.com</p>
    </footer>

    <script>
        $(document).ready(function() {
            $('#scanForm').on('submit', function(e) {
                e.preventDefault();
                $('#progress-bar').css('width', '0%').attr('aria-valuenow', 0);
                $('#results').html('');
                var directory = $('#scan_directory').val();
                if (directory) {
                    $.ajax({
                        url: '',
                        method: 'POST',
                        data: {
                            action: 'scan_directory',
                            scan_directory: directory
                        },
                        success: function(response) {
                            var files = response.files;
                            var totalFiles = files.length;
                            var processedFiles = 0;

                            function scanNextFile() {
                                if (processedFiles < totalFiles) {
                                    var file = files[processedFiles];
                                    $.ajax({
                                        url: '',
                                        method: 'POST',
                                        data: {
                                            action: 'scan_file',
                                            file_path: file
                                        },
                                        success: function(fileResponse) {
                                            processedFiles++;
                                            var progress = Math.round((processedFiles / totalFiles) * 100);
                                            $('#progress-bar').css('width', progress + '%').attr('aria-valuenow', progress);

                                            if (fileResponse.vulnerabilities.length > 0) {
                                                var resultHtml = '<div class="list-group-item">';
                                                resultHtml += '<strong>الملف:</strong> ' + fileResponse.file + '<br>';
                                                $.each(fileResponse.vulnerabilities, function(i, vulnerability) {
                                                    resultHtml += '<span class="text-danger">- ' + vulnerability + '</span><br>';
                                                });
                                                resultHtml += '</div>';
                                                $('#results').append(resultHtml);
                                            }
                                            setTimeout(scanNextFile, 500); // تأخير بمقدار 500 مللي ثانية بين كل عملية فحص لتقليل استهلاك المعالج
                                        }
                                    });
                                }
                            }

                            scanNextFile();
                        }
                    });
                }
            });
        });
    </script>
</body>
</html>