// amnezia-doctor — открыть файл через меню «Поделиться» macOS в заданном сервисе.
//   osascript -l JavaScript share.js <файл> <имя сервиса> [макс. секунд]
// Печатает: shared | cancelled | timeout | no-service | cannot-perform.
// Процесс живёт, пока окно сервиса открыто: без живого хоста окно расширения закрывается.
ObjC.import("AppKit");

var result = "";

ObjC.registerSubclass({
  name: "ADShareDelegate",
  protocols: ["NSSharingServiceDelegate"],
  methods: {
    "sharingService:didShareItems:": {
      types: ["void", ["id", "id"]],
      implementation: function (service, items) { result = "shared"; }
    },
    "sharingService:didFailToShareItems:error:": {
      types: ["void", ["id", "id", "id"]],
      implementation: function (service, items, error) { result = "cancelled"; }
    }
  }
});

function run(argv) {
  var app = $.NSApplication.sharedApplication;
  app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
  var items = $([$.NSURL.fileURLWithPath(argv[0])]);
  var services = $.NSSharingService.sharingServicesForItems(items);
  var svc = null;
  for (var i = 0; i < services.count; i++) {
    var s = services.objectAtIndex(i);
    if (ObjC.unwrap(s.name) === argv[1]) { svc = s; break; }
  }
  if (!svc) return "no-service";
  if (!svc.canPerformWithItems(items)) return "cannot-perform";

  var delegate = $.ADShareDelegate.alloc.init;
  svc.delegate = delegate;
  app.activateIgnoringOtherApps(true);
  svc.performWithItems(items);

  var deadline = Date.now() + 1000 * Number(argv[2] || 600);
  while (result === "" && Date.now() < deadline) {
    $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.5));
  }
  return result || "timeout";
}
