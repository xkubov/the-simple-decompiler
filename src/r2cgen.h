/**
 * @file include/r2plugin/r2cgen.h
 * @brief C code generation and token marking.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license.
 */

#ifndef RETDEC_R2PLUGIN_R2CGEN_H
#define RETDEC_R2PLUGIN_R2CGEN_H

#include <map>
#include <optional>
#include <rapidjson/document.h>

#include <r_util/r_annotated_code.h>

namespace retdec {
namespace r2plugin {

class R2CGenerator {
public:
	RAnnotatedCode* generateOutput(const std::string &rdoutJson) const;

protected:
	RAnnotatedCode* provideAnnotations(const rapidjson::Document &root) const;
	std::optional<RSyntaxHighlightType> highlightTypeForToken(const std::string &token) const;

private:
	static std::map<const std::string, RSyntaxHighlightType> _hig2token;
};

}
}

#endif /*RETDEC_R2PLUGIN_R2CGEN_H*/
