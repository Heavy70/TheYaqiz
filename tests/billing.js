/* Billing / subscription / storage / account-lock phishing, often WITHOUT a visible link (screenshots of emails with a button).
   Added 2026-11-22 after a real miss: a "payment method has expired" cloud-storage email scored 0. */
module.exports = [
/* scams (x) */
['Your payment method has expired. Please update your payment details to avoid service interruption. Subscription ID: CLDSTRG-92837465 Product: Cloud Storage Without enough Cloud space, you may not be able to store all your data and files in the Cloud service. This service allows you to store photos, videos, documents, and more securely and access them from any device. Update payment method','x'],
['Apple ID: your payment was declined. Update your billing information within 48 hours or your iCloud storage will be deleted. Update now','x'],
['Netflix: We couldn\'t process your last payment. Please update your payment details to avoid service interruption. Update account','x'],
['Your iCloud storage is full. Your photos and videos will be deleted today. Upgrade now for only 1 AED','x'],
['Your cloud storage is full! Your photos and files will be removed in 24 hours. Click below to get 50GB extra free','x'],
['عزيزي العميل، انتهت صلاحية طريقة الدفع الخاصة بك. يرجى تحديث بيانات الدفع لتجنب انقطاع الخدمة.','x'],
['مساحة التخزين السحابية ممتلئة، سيتم حذف صورك وملفاتك خلال 24 ساعة. اضغط هنا للترقية','x'],
['تعذر إتمام عملية الدفع لاشتراكك. حدّث طريقة الدفع الآن لتجنب إيقاف حسابك','x'],
['Your mailbox is almost full. Verify your account now to avoid losing incoming emails','x'],
['Your account has been locked due to suspicious activity. Tap the button below to verify your identity','x'],
['Microsoft 365: your subscription has expired and your files will be deleted. Renew now to keep access','x'],
['Your Norton subscription has been renewed for 1,499 AED. If you did not authorise this payment, call our refund team now','x','w'],
['Amazon: your Prime membership payment failed. Update your card details to keep your benefits','x'],
['Your Google Photos backup has stopped: payment method declined. Update your billing details to avoid losing your photos','x'],
['Final notice: your subscription will be cancelled today. Confirm your card details to continue','x'],
['اشتراكك في خدمة التخزين منتهي. أكد بيانات بطاقتك لاستعادة ملفاتك قبل حذفها','x'],
['Your account will be deleted within 24 hours unless you confirm your payment information','x'],
['Payment unsuccessful: your Disney+ membership is on hold. Update your payment method to resume watching','x'],
/* genuine (s, or w allowed) */
['Your Apple subscription to iCloud+ has been renewed. Amount: 3.99 AED. You can manage your subscriptions in Settings.','s','w'],
['Payment received: thank you for paying your du bill of 250 AED.','s'],
['Your Netflix payment was declined. To keep watching, update your payment method in the Netflix app or at https://www.netflix.com/youraccount','s','w'],
['تم تجديد اشتراكك بنجاح. شكرًا لاستخدامك خدماتنا.','s'],
['Your iCloud storage is 80% full. You can manage storage in Settings > iCloud.','s','w'],
['Your receipt from Apple: iCloud+ 50GB, 3.99 AED. Order ID MK2H7. If you have questions, visit the App Store app.','s','w'],
['تم خصم 45 درهم من بطاقتك المنتهية بـ 4417 لاشتراك التخزين. لإدارة الاشتراك افتح الإعدادات في هاتفك.','s','w']
];
