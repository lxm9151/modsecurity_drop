/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include "modsecurity/rules.h"

#include "modsecurity/rule_message.h"

#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "src/utils/string.h"

namespace modsecurity {


std::string RuleMessage::_details(const RuleMessage *rm) {
    std::string msg;

    msg.append(" [file \"" + std::string(rm->m_ruleFile) + "\"]");
    msg.append(" [line \"" + std::to_string(rm->m_ruleLine) + "\"]");
    msg.append(" [id \"" + std::to_string(rm->m_ruleId) + "\"]");
    msg.append(" [rev \"" + rm->m_rev + "\"]");
    msg.append(" [msg \"" + rm->m_message + "\"]");
    msg.append(" [data \"" + utils::string::limitTo(200, rm->m_data) + "\"]");
    msg.append(" [severity \"" +
        std::to_string(rm->m_severity) + "\"]");
    msg.append(" [ver \"" + rm->m_ver + "\"]");
    msg.append(" [maturity \"" + std::to_string(rm->m_maturity) + "\"]");
    msg.append(" [accuracy \"" + std::to_string(rm->m_accuracy) + "\"]");
    for (auto &a : rm->m_tags) {
        msg.append(" [tag \"" + a + "\"]");
    }
    msg.append(" [hostname \"" + std::string(rm->m_serverIpAddress) \
        + "\"]");
    msg.append(" [uri \"" + utils::string::limitTo(200, rm->m_uriNoQueryStringDecoded) + "\"]");
    msg.append(" [unique_id \"" + rm->m_id + "\"]");
    msg.append(" [ref \"" + utils::string::limitTo(200, rm->m_reference) + "\"]");

    return msg;
}


std::string RuleMessage::_errorLogTail(const RuleMessage *rm) {
    std::string msg;

    msg.append("[hostname \"" + std::string(rm->m_serverIpAddress) + "\"]");
    msg.append(" [uri \"" + utils::string::limitTo(200, rm->m_uriNoQueryStringDecoded) + "\"]");
    msg.append(" [unique_id \"" + rm->m_id + "\"]");

    return msg;
}


std::string RuleMessage::log(const RuleMessage *rm, int props, int code) {
    std::string msg("");

    if (props & ClientLogMessageInfo) {
        msg.append("[client " + std::string(rm->m_clientIpAddress) + "] ");
    }

    if (rm->m_isDisruptive) {
        msg.append("ModSecurity: Access denied with code ");
        if (code == -1) {
            msg.append("%d");
        } else {
            msg.append(std::to_string(code));
        }
        msg.append(" (phase ");
        msg.append(std::to_string(rm->m_rule->m_phase - 1) + "). ");
    } else {
        msg.append("ModSecurity: Warning. ");
    }

    msg.append(rm->m_match);
    msg.append(_details(rm));

    if (props & ErrorLogTailLogMessageInfo) {
        msg.append(" " + _errorLogTail(rm));
    }
    return modsecurity::utils::string::toHexIfNeeded(msg);
}


}  // namespace modsecurity
