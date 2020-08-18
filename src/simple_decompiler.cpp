#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

#include <r_core.h>
#include <retdec/retdec.h>
#include <retdec/config/config.h>

#include "r2cgen.h"

/// Plugin activation sequence.
#define CMD "pdq"

namespace fs = std::filesystem;

retdec::config::Config loadDefaultConfig()
{
	// Returns plugin home:
	// ~/.local/share/radare2/plugins/
	auto plugdir = r_str_home(R2_HOME_PLUGINS);
	auto plugPath = fs::path(plugdir);
	// Default config is always installed with the plugin.
	auto configPath = plugPath/"decompiler-config.json";

	// Config must be regular file - exception will be thrown otherwise.
	if (!fs::is_regular_file(configPath)) {
		throw std::runtime_error("unable to locate decompiler configuration");
	}

	// Loads configuration from file - also contains default config.
	auto rdConf = retdec::config::Config::fromFile(configPath.string());
	// Paths to the signatures, etc.
	rdConf.parameters.fixRelativePaths(plugPath.string());

	return rdConf;
}

retdec::common::AddressRange currentAddressRange(const RCore& core)
{
	RAnalFunction *cf = r_anal_get_fcn_in(core.anal, core.offset, R_ANAL_FCN_TYPE_NULL);
	if (cf == nullptr) {
		throw std::runtime_error("No function at the offset: "
			+ std::to_string(core.offset));
	}

	auto start = r_anal_function_min_addr(cf);
	auto end = r_anal_function_max_addr(cf);
	
	return {start, end};
}

void decompileWithRetDec(const RCore& core)
{
	auto config = loadDefaultConfig();

	config.parameters.setInputFile(core.file->binb.bin->file);
	config.parameters.setOutputFormat("plain");
	config.parameters.setIsVerboseOutput(false);
	config.parameters.selectedRanges.insert(currentAddressRange(core));

	std::string retdecOutput;
	if (retdec::decompile(config, &retdecOutput)) {
		std::cout << "Decompilation was not successful" << std::endl;
	}
	else {
		std::cout << retdecOutput << std::endl;
	}
}

void decompileWithRetDecAnnotated(const RCore& core)
{
	auto config = loadDefaultConfig();

	config.parameters.setInputFile(core.file->binb.bin->file);
	config.parameters.setOutputFormat("json");
	config.parameters.setIsVerboseOutput(false);
	config.parameters.selectedRanges.insert(currentAddressRange(core));

	std::string retdecOutput;
	if (retdec::decompile(config, &retdecOutput)) {
		std::cout << "Decompilation was not successful" << std::endl;
		return;
	}

	retdec::r2plugin::R2CGenerator outgen;
	auto rcode = outgen.generateOutput(retdecOutput);

	r_core_annotated_code_print(rcode, nullptr);
}

/**
 * R2 console registration method. This method is called
 * after each command typed into r2. If the function wants
 * to respond on provided command, provides response and returns true.
 * Activation method for this function is matching prefix of the input.
 *  -> prefix(input) == CMD_PREFIX
 *
 * Otherwise the function must return false which will indicate that
 * other command should be executed.
 */
static int callback(void *user, const char* input)
{

	RCore* core = (RCore*)user;
	if (std::strncmp(input, CMD, sizeof(CMD)-1) != 0)
		return false;

	try {
		// decompileWithRetDec(*core);
		decompileWithRetDecAnnotated(*core);
	}
	catch (const std::exception& e) {
		std::cout << "error: " << e.what() << std::endl;
	}

	return true;
}

// Structure containing plugin info.
RCorePlugin r_core_plugin_retdec = {
	/* .name = */ "simple-decompiler",
	/* .desc = */ "Simple decompiler example.",
	/* .license = */ "MIT",
	/* .author = */ "Avast",
	/* .version = */ "0.1",
	/* .call = */ callback,
	/* .init = */ nullptr,
	/* .fini = */ nullptr
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C"
#endif

// This will register the r2plugin in r2 console.
R_API RLibStruct radare_plugin = {
	/* .type = */ R_LIB_TYPE_CORE,
	/* .data = */ &r_core_plugin_retdec,
	/* .version = */ R2_VERSION,
	/* .free = */ nullptr,
	/* .pkgname */ "simple-decompiler"
};

#endif
